import datetime
import json
import os
import re
import subprocess
import time
import uuid
from datetime import timedelta

import click
import psycopg2
import requests

from ..bp_lookup.bp_lookup import GHElookup
from ..gd_ingest.gd_ingest import GDIngest
from ..github_client.github import GitHub
from ..github_client.github_app import GitHubApp
from ..notification.gd_report_generator import GdReportGenerator
from ..notification.gd_report_generator import OrgSetController
from ..pi_cleaner.pi_cleaner import PICleaner
from ..scan_worker.commit import Commit
from ..scan_worker.secret import Secret
from ..secret_corpus_db.db_biz import DbBiz
from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import get_commit_encrypted_columns_all
from ..secret_corpus_db.gd_db_tools import get_commit_encrypted_columns_by_id
from ..secret_corpus_db.gd_db_tools import get_live_tokens
from ..secret_corpus_db.gd_db_tools import get_token_by_id_limited
from ..secret_corpus_db.gd_db_tools import get_tokens_by_type
from ..secret_corpus_db.gd_db_tools import update_commit_encrypted_columns_by_id
from ..secret_corpus_db.gd_db_tools import update_token_hash_by_id
from ..secret_corpus_db.gd_db_tools import update_token_uuid_by_id
from ..secret_corpus_db.vault import Vault
from ..security.security import Decryptor
from ..security.security import DeterministicCryptor
from ..security.security import Encryptor
from ..util.conf import ConfUtil
from ..util.log_util import LogUtil
from ..validation.revalidation import Revalidator


class SecretUtil(object):

    def __init__(self, pri_key, pub_key):
        self.decryptor = Decryptor()
        self.encryptor = Encryptor()
        self.deterministic_cryptor = DeterministicCryptor()
        self.db_conn = connect_db()
        self.github_app = GitHubApp()

    def encrypt(self, text: str):
        return self.encryptor.encrypt(text)

    def decrypt(self, encrypted_text: str) -> str:
        return self.decryptor.decrypt(encrypted_text)

    def encrypt_deterministic(self, text: str):
        return self.deterministic_cryptor.encrypt(text)

    def decrypt_deterministic(self, encrypted_text: str) -> str:
        return self.deterministic_cryptor.decrypt(encrypted_text)

    def get_token_by_id_from_db(self, token_id: str):
        """
        Return a token by id.

        Return: tuple of (token_id, token_cred_str, token_uuid), or None if token with
        id does not exists
        """
        tokens = get_token_by_id_limited(self.db_conn, token_id)
        if tokens:
            token = tokens[0]
            token_id, encrypted_text, token_uuid, encrypted_other_factors, token_type = token
            return (
                token_id,
                self.decrypt(encrypted_text),
                token_uuid,
                self.decrypt(encrypted_other_factors),
                token_type,
            )
        else:
            return None

    def get_secret_by_token_id_from_db(self, token_id: str) -> Secret:
        return DbBiz().get_secret_from_db(token_id)

    def get_tokens_list_by_type_from_db(self, token_type: str):
        """
        Return a list of tokens by type.

        Return: a list of tuple, each tuple is (token_id, token_cred_str, token_uuid)
        """
        tokens = get_tokens_by_type(self.db_conn, token_type)

        token_list = []
        for token in tokens:
            token_id, encrypted_text, token_uuid, _, _, is_live = token
            token_list.append(
                (token_id, self.decrypt(encrypted_text), token_uuid, is_live),
            )

        return token_list

    def get_tokens_dict_by_type_from_db(self, token_type: str):
        tokens = get_tokens_by_type(self.db_conn, token_type)

        token_dict = {}
        for token in tokens:
            _, encrypted_text, _, _, _, _ = token
            decrypted_text = self.decrypt(encrypted_text)
            token_as_list = list(token)
            token_as_list[4] = self.decrypt(token[4])
            if not token_dict.get(decrypted_text):
                token_dict[decrypted_text] = token_as_list
        return token_dict

    def get_commit_encrypted_columns_by_id_from_db(self, commit_id):
        return get_commit_encrypted_columns_by_id(self.db_conn, commit_id)

    def get_commit_encrypted_columns_from_db(self):
        return get_commit_encrypted_columns_all(self.db_conn)

    def get_live_tokens_from_db(self):
        return get_live_tokens(self.db_conn)

    def update_commit_encrypted_columns_by_id_in_db(
        self, commit_id,
        encrypted_commit_hash,
        encrypted_branch_name,
        encrypted_filename,
        encrypted_linenumber,
        encrypted_location_url,
    ):
        update_commit_encrypted_columns_by_id(
            self.db_conn,
            commit_id,
            encrypted_commit_hash,
            encrypted_branch_name,
            encrypted_filename,
            encrypted_linenumber,
            encrypted_location_url,
        )

    def update_token_hash_by_id_in_db(self, token_id: str, token_hash: str):
        update_token_hash_by_id(self.db_conn, token_id, token_hash)

    def update_token_uuid_by_id_in_db(self, token_id: str, token_uuid: str):
        update_token_uuid_by_id(self.db_conn, token_id, token_uuid)


github_host = ConfUtil.load_github_conf()['host']


@click.group()
@click.option(
    '--pri_key', required=True, envvar='GD_PRI_KEY_FILENAME',
    help='The name of the private key used in encryption. Read from environment variable GD_PRI_KEY_FILENAME',
)
@click.option(
    '--pub_key', required=True, envvar='GD_PUB_KEY_FILENAME',
    help='The name of the public key used in encryption. Read from environment variable GD_PUB_KEY_FILENAME',
)
@click.option(
    '--db_conf', required=True, envvar='GD_DB_CONF',
    help='The configuration file containing database info. Read from environment variable GD_DB_CONF',
)
@click.option(
    '--gh_conf', required=True, envvar='GD_GITHUB_CONF',
    help='The configuration file for connecting to GitHub enterprise.',
)
@click.option(
    '--app_id', required=True, envvar='APP_ID',
    help='The app ID of the GitHub app used to access private repositories.',
)
@click.option(
    '--app_private_key', required=True, envvar='APP_PRIVATE_KEY_FILENAME',
    help='The private key used to sign JWT requests to GitHub while authenticated as the app.',
)
@click.pass_context
def main(ctx, pri_key, pub_key, db_conf, gh_conf, app_id, app_private_key):
    """
    CLI for interigate DB to decrypt stored tokens.
    """
    LogUtil.set_root_logger_console()

    ctx.ensure_object(dict)
    ctx.obj['secret_util'] = SecretUtil(pri_key, pub_key)


@main.command()
@click.argument('raw_text')
@click.pass_context
def encrypt_text(ctx, raw_text):
    vs = ctx.obj['secret_util']
    print(vs.encrypt(raw_text))


@main.command()
@click.argument('encrypted_text')
@click.pass_context
def decrypt_text(ctx, encrypted_text):
    vs = ctx.obj['secret_util']
    print(vs.decrypt(encrypted_text))


@main.command()
@click.argument('raw_text')
@click.pass_context
def encrypt_text_deterministic(ctx, raw_text):
    vs = ctx.obj['secret_util']
    print('\\x' + vs.encrypt_deterministic(raw_text).hex())


@main.command()
@click.argument('encrypted_text')
@click.pass_context
def decrypt_text_deterministic(ctx, encrypted_text):
    vs = ctx.obj['secret_util']
    print(vs.decrypt_deterministic(bytearray.fromhex(encrypted_text[1:])))


@main.command()
@click.argument('token_id')
@click.pass_context
def decrypt_token_by_id(ctx, token_id):
    """
    Decrypt the token from database by token id field.
    """
    db = DbBiz()
    secret = db.get_secret_from_db(token_id)

    print(
        f'id={secret.id} uuid={secret.uuid} secret={secret.secret} type="{secret.secret_type}"'
        f' other_factors={secret.other_factors} owner={secret.owner_email} valid={secret.live}''',
    )


@main.command()
@click.argument('token_uuid')
@click.pass_context
def decrypt_token_by_uuid(ctx, token_uuid):
    """
    Decrypt the token from database by token id field.
    """
    db = DbBiz()
    secret = db.get_secret_from_db_by_uuid(token_uuid)
    secret.lookup_token_owner()

    print(
        f'uuid={secret.uuid} id={secret.id} secret={secret.secret} type="{secret.secret_type}"'
        f' other_factors={secret.other_factors} owner={secret.owner_email} valid={secret.live}''',
    )


@main.command()
@click.argument('token')
def encode_ghe_token(token):
    print(_encode_ghe_token(token))


def _encode_ghe_token(token):
    """
    Encode GHE access token in it's own magical way
    """
    encoded_token = subprocess.getoutput(
        f'''echo "{token}" | tr -d "\n" | gsha256sum | tr -d "\n -" | xxd -r -p | base64''',
    )

    return encoded_token


def get_ghe_token_creation_time(token):
    token_hash = _encode_ghe_token(token)

    # SSH into GHE mysql replica to query the date
    # The return time is in UTC
    cmd = f'''ssh bane -- 'mysql -u root --database github_enterprise --skip-column-names --execute "select created_at from oauth_accesses where hashed_token=\\"{token_hash}\\";"' '''  # noqa E501

    cmd_output = subprocess.getoutput(cmd)
    created_date_lines = [
        line
        for line in cmd_output.split('\n')
        if line and not line.startswith('Warning:')
    ]

    created_date = created_date_lines and created_date_lines[-1] or ''
    return created_date


def _check_creation_date(secret):
    token_id = secret.id

    # 1. validate token is GHE token
    # 2. encode token as token hash
    # 3. query GHE db with the token hash to get creation date
    # 4. report time difference

    if secret.secret_type != 'GitHub Credentials':
        print(f'Token {token_id} has wrong token type "{secret.secret_type}"')
        return

    if secret.live is not True:
        print(f'Token {token_id} is no longer valid')
        return

    creation_time = get_ghe_token_creation_time(secret.secret)
    if not creation_time:
        print(f'Token {token_id} can not locate creation time')
        return

    # creation_time=2018-02-21 21:50:24
    # found_time=2019-09-24 17:59:11.223371+00:00
    found_time_dt = secret.first_identified.replace(tzinfo=None)
    creation_time_dt = datetime.datetime.strptime(creation_time, '%Y-%m-%d %H:%M:%S')
    time_diff = found_time_dt - creation_time_dt
    hours_after_creation = int(time_diff.total_seconds() / 3600)
    print(
        f'id={secret.id} hours_after_creation={hours_after_creation}'
        f' creation_time={creation_time_dt} found_time={found_time_dt}',
    )


@main.command()
@click.argument('token_id')
@click.pass_context
def check_creation_date_by_id(ctx, token_id):
    """
    Check the creation time for GHE token by id
    """
    db = DbBiz()
    secret = db.get_secret_from_db(token_id)

    _check_creation_date(secret)


@main.command()
@click.pass_context
def check_creation_date_for_ghe_tokens(ctx):
    """
    Check the creation time for all GHE tokens
    """

    db = DbBiz()
    token_ids = db.get_live_tokens()
    for token_id in token_ids:
        secret = db.get_secret_from_db(token_id)
        if secret.secret_type != 'GitHub Credentials':
            continue

        _check_creation_date(secret)


@main.command()
@click.argument('token_id')
@click.pass_context
def revalidated_token_by_id(ctx, token_id):
    """
    Revalidate a token in database by token id field.
    """

    db = DbBiz()
    secret = db.get_secret_from_db(token_id)

    print('before revalidate')
    print(
        f'id={secret.id} secret={secret.secret} type="{secret.secret_type}" other_factors={secret.other_factors}'
        f' owner={secret.owner_email} valid={secret.live} last_test_date={secret.last_test_date}'
        f' last_test_success={secret.last_test_success} remediation_date={secret.remediation_date}',
    )

    revalidator = Revalidator()
    revalidator.revalidate(token_id)

    secret = db.get_secret_from_db(token_id)

    print('after revalidate')
    print(
        f'id={secret.id} secret={secret.secret} type="{secret.secret_type}" other_factors={secret.other_factors}'
        f' owner={secret.owner_email} valid={secret.live} last_test_date={secret.last_test_date}'
        f' last_test_success={secret.last_test_success} remediation_date={secret.remediation_date}',
    )


@main.command()
@click.argument('token_id')
@click.pass_context
def update_owner_by_id(ctx, token_id):
    """
    Look up and fill out owner by id
    """
    db = DbBiz()
    secret = db.get_secret_from_db(token_id)

    print('before fix')
    print(
        f'id={secret.id} secret={secret.secret} type="{secret.secret_type}" other_factors={secret.other_factors}'
        f' owner={secret.owner_email}''',
    )

    revalidator = Revalidator()
    revalidator.fix_owner(token_id)

    secret = db.get_secret_from_db(token_id)

    print('after fix')
    print(
        f'id={secret.id} secret={secret.secret} type="{secret.secret_type}" other_factors={secret.other_factors}'
        f' owner={secret.owner_email}''',
    )


@main.command()
@click.argument(
    'token_type', type=click.Choice([
        'Slack Token',
        'SoftLayer Credentials', 'Test Secret', 'IBM Cloud IAM Key', 'Artifactory Credentials',
    ]),
)
@click.option(
    '--replace', type=bool, default=False, required=False, is_flag=True,
    help='Replace the existing owner, if owner exists.',
)
@click.pass_context
def update_owners_by_type(ctx, token_type, replace):
    """
    Look up and fill out owner by token type
    """
    vs = ctx.obj['secret_util']
    db = DbBiz()
    revalidator = Revalidator()

    tokens = vs.get_tokens_list_by_type_from_db(token_type)
    for token_id, token_cred, _, is_live in tokens:
        if not is_live:
            continue
        revalidator.fix_owner(token_id, replace=replace)
        secret = db.get_secret_from_db(token_id)

        print('after fix')
        print(
            f'id={secret.id} secret={secret.secret} type="{secret.secret_type}" other_factors={secret.other_factors}'
            f' owner={secret.owner_email}''',
        )


@main.command()
@click.option('--by', type=click.Choice(['day', 'week', 'month']), default='day')
@click.argument(
    'token_type', type=click.Choice(
        [
            'Slack Token',
            'SoftLayer Credentials',
            'Test Secret',
            'AWS Access Key',
            'GitHub Credentials',
        ],
    ),
)
@click.pass_context
def report_token(ctx, by, token_type):
    vs = ctx.obj['secret_util']
    token_dict = vs.get_tokens_dict_by_type_from_db(token_type)

    date_dict = {}
    for token in token_dict.values():
        _, _, _, found_date, _ = token

        if by == 'day':
            by_key = str(found_date)
        elif by == 'week':
            start = found_date - timedelta(days=found_date.weekday())
            by_key = f'week of {start}'
        elif by == 'month':
            # Take the year and month from date output, such as 2019-07
            by_key = str(found_date)[:7]

        date_token_count = date_dict.get(by_key, 0)
        date_token_count = date_token_count + 1
        date_dict[by_key] = date_token_count

    for by_key in sorted(date_dict.keys()):
        print(f'{by_key}={date_dict[by_key]}')


def validate_token(token_type, raw_token, other_factors):
    if type(other_factors) is str:
        other_factors = json.loads(other_factors)

    secret = Secret(raw_token, token_type)
    secret.other_factors = other_factors
    valid = secret.verify()
    owner = secret.lookup_token_owner()
    return valid, owner


@main.command()
@click.argument('token_type', type=click.Choice(['Slack Token', 'SoftLayer Credentials']))
@click.pass_context
def verify_token(ctx, token_type):
    '''
    Verify token by type
    '''
    vs = ctx.obj['secret_util']
    token_dict = vs.get_tokens_dict_by_type_from_db(token_type)

    print(f'Total unique token count: {len(token_dict.keys())}')

    valid_token_count = 0
    for raw_token, (token_id, _, _, _, other_factors) in token_dict.items():
        print(f'other_factors: {other_factors}')
        valid, owner = validate_token(token_type, raw_token, other_factors)
        print(
            f'valid={valid} token={raw_token} token_id={token_id} owner={owner}',
        )
        if valid:
            valid_token_count = valid_token_count + 1

    print(f'{valid_token_count} slack tokens are still valid.')


@main.command()
@click.argument('token_id')
@click.pass_context
def verify_token_by_id(ctx, token_id):
    '''
    Verify token display owner by id
    '''
    vs = ctx.obj['secret_util']
    _, raw_token, _, other_factors, token_type = vs.get_token_by_id_from_db(token_id)

    valid, owner = validate_token(token_type, raw_token, other_factors)
    print(
        f'valid={valid} token={raw_token} token_id={token_id} owner={owner}',
    )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out hash, but not update',
)
@click.pass_context
def update_uniqueness_hash_for_all_commits(ctx, dry_run):
    commits = DbBiz().get_all_commits_from_db()
    for commit in commits:
        commit.generate_uniqueness_hash()
        if not dry_run:
            print(
                f'Updating uniqueness_hash for commit_id {commit.commit_id} '
                f'to {commit.uniqueness_hash}',
            )
            DbBiz().update_commit_in_db(commit)
        else:
            print(f'commit_id {commit.commit_id} uniqueness_hash {commit.uniqueness_hash}')


@main.command()
@click.argument('token_uuid')
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out commit missing pusher email, but not update',
)
@click.pass_context
def update_pusher_email_for_commits_by_token_uuid(ctx, token_uuid, dry_run):
    print(f'Dryrun={dry_run}')
    db = DbBiz()
    ghe_lookup = GHElookup()

    secret = db.get_secret_from_db_by_uuid(token_uuid)
    commits = db.get_commits_by_token_id_from_db(secret.id)
    for commit in commits:
        if commit.pusher_username != '' and commit.pusher_email == '':
            print(
                f'Found commit_id={commit.commit_id} pusher_username={commit.pusher_username}'
                f'pusher_email={commit.pusher_email}',
            )
            commit.pusher_email = ghe_lookup.ghe_email_lookup(commit.pusher_username)
            if not dry_run:
                # look up owner
                db.update_commit_in_db(commit)
                print(f'Updated pusher email to {commit.pusher_email}')
            else:
                print(f'will update pusher email to {commit.pusher_email}')


@main.command()
@click.argument('token_uuid')
@click.pass_context
def get_commits_by_token_uuid(ctx, token_uuid):
    """
    List out all commits assocaited with one token by UUID
    """
    db = DbBiz()
    secret = db.get_secret_from_db_by_uuid(token_uuid)
    commits = db.get_commits_by_token_id_from_db(secret.id)
    for commit in commits:
        print(
            f'commit_id={commit.commit_id} '
            f'pusher_username={commit.pusher_username} pusher_email={commit.pusher_email}  '
            f'author_name={commit.author_name} author_email={commit.author_email} '
            f'committer_name={commit.committer_name} committer_email={commit.committer_email} '
            f'location_url={commit.location_url} filename={commit.filename} linenumber={commit.linenumber}',
        )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out hash, but not update',
)
@click.pass_context
def update_hash_for_all_tokens(ctx, dry_run):
    """
    Generate / update the token hash from raw token text.
    """
    vs = ctx.obj['secret_util']
    token_ids = DbBiz().get_all_tokens()

    for token_id in token_ids:
        if isinstance(token_id, tuple):
            token_id = token_id[0]
        secret = DbBiz().get_secret_from_db(token_id)

        # if we already cleared the hashed secret as part of PI cleaning,
        # don't update it, leave it the same
        if secret.hashed_secret is not None and secret.hashed_secret != '':
            secret.generate_hashed_secret()
            token_hash = secret.hashed_secret
        else:
            token_hash = secret.hashed_secret

        if not dry_run and token_hash != '':
            vs.update_token_hash_by_id_in_db(token_id, token_hash)
            print(
                f"Updated token_id={token_id} hash to '{token_hash}'",
            )
        else:
            print(
                f'token_id={token_id} token_hash={token_hash}',
            )


@main.command()
@click.argument('token_id')
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out uuid, but not update',
)
@click.pass_context
def update_uuid_by_id(ctx, token_id, dry_run):
    """
    Generate / update the token uuid.
    """
    vs = ctx.obj['secret_util']
    token = vs.get_token_by_id_from_db(token_id)
    if not token:
        print(f'Can not find token with id {token_id}')
        return

    token_id, token_cred, old_token_uuid, _, _ = (token)
    token_uuid = str(uuid.uuid4())

    if not dry_run and not old_token_uuid:
        vs.update_token_uuid_by_id_in_db(token_id, token_uuid)
        print(
            f"Updated token_id={token_id} uuid to '{token_uuid}'",
        )
    else:
        print(
            f'token_id={token_id} token_cred={token_cred} token_uuid={token_uuid}',
        )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out uuid, but not update',
)
@click.argument('token_type', type=click.Choice(['Slack Token', 'SoftLayer Credentials', 'Test Secret']))
@click.pass_context
def update_uuid_by_type(ctx, dry_run, token_type):
    """
    Generate / update the token uuid.
    """
    vs = ctx.obj['secret_util']

    tokens = vs.get_tokens_list_by_type_from_db(token_type)
    for token_id, token_cred, old_token_uuid, is_live in tokens:
        token_uuid = str(uuid.uuid4())

        if not dry_run and not old_token_uuid:
            vs.update_token_uuid_by_id_in_db(token_id, token_uuid)
            print(
                f"Updated token_id={token_id} uuid to '{token_uuid}'",
            )
        else:
            print(
                f'token_id={token_id} token_cred={token_cred} token_uuid={token_uuid}',
            )


@main.command()
@click.argument('filename')
@click.pass_context
def vmt_csv(ctx, filename):
    """
    Generate the report for VMT.
    """
    gd_report = GdReportGenerator()
    gd_report.generate_csv_from_db(filename)


def _encrypt_single_commit(vs, dry_run, commit_id, commit_hash, commit_branch, filename, linenumber, location_url):
    commit_hash = GdReportGenerator.decode_hex(commit_hash)
    commit_branch = GdReportGenerator.decode_hex(commit_branch)
    filename = GdReportGenerator.decode_hex(filename)
    linenumber = GdReportGenerator.decode_hex(linenumber)
    location_url = GdReportGenerator.decode_hex(location_url)

    if location_url and location_url.startswith(github_host):
        location_url = 'https://' + location_url

    # leverage Commit and Secret class to encrypt proper fields
    tmp_commit = Commit(commit_hash, 'repo_slug', commit_branch)
    tmp_commit.location_url = location_url
    tmp_secret = Secret('fake secret', 'fake type')
    tmp_secret.filename = filename
    tmp_secret.linenumber = linenumber

    print(
        f'Raw content: commit_id={commit_id}, commit_hash={commit_hash}, commit_branch={commit_branch}'
        f', filename={filename}, linenumber={linenumber}, location_url={location_url}',
    )

    if dry_run:
        print(
            f'After update: commit_id={commit_id}, commit_hash={tmp_commit.encrypted_commit_hash}'
            f', commit_branch={tmp_commit.encrypted_branch_name}, filename={tmp_commit.encrypted_filename}'
            f', linenumber={tmp_commit.encrypted_linenumber}, location_url={tmp_commit.encrypted_location_url}',
        )
    else:
        try:
            vs.update_commit_encrypted_columns_by_id_in_db(
                commit_id,
                tmp_commit.encrypted_commit_hash,
                tmp_commit.encrypted_branch_name,
                tmp_commit.encrypted_filename,
                tmp_commit.encrypted_linenumber,
                tmp_commit.encrypted_location_url,
            )
        except psycopg2.errors.UniqueViolation:
            print(f'commit_id={commit_id} violates uniqueness constraint')

        print(
            f'After update: commit_id={commit_id}, commit_hash={tmp_commit.encrypted_commit_hash}'
            f', commit_branch={tmp_commit.encrypted_branch_name}, filename={tmp_commit.encrypted_filename}'
            f', linenumber={tmp_commit.encrypted_linenumber}, location_url={tmp_commit.encrypted_location_url}',
        )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out what would be updated',
)
@click.argument('commit_id')
@click.pass_context
def re_encrypt_commit_by_id(ctx, dry_run, commit_id):
    """
    For one row in commit table, re-encrypt all need to encrypt columns.
    """
    vs = ctx.obj['secret_util']
    print(f'dry_run: {dry_run}')

    commits = vs.get_commit_encrypted_columns_by_id_from_db(commit_id)
    for commit in commits:
        commit_id, commit_hash, commit_branch, filename, linenumber, location_url = (commit)

        _encrypt_single_commit(vs, dry_run, commit_id, commit_hash, commit_branch, filename, linenumber, location_url)


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out what would be updated',
)
@click.pass_context
def re_encrypt_commits(ctx, dry_run):
    """
    For all rows in commit table, re-encrypt all need to encrypt columns.
    """
    vs = ctx.obj['secret_util']
    print(f'dry_run: {dry_run}')

    commits = vs.get_commit_encrypted_columns_from_db()
    for commit in commits:
        commit_id, commit_hash, commit_branch, filename, linenumber, location_url = (commit)

        _encrypt_single_commit(
            vs, dry_run, commit_id, commit_hash, commit_branch,
            filename, linenumber, location_url,
        )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out what would be updated',
)
@click.pass_context
def move_secrets_to_vault(ctx, dry_run):
    vs = ctx.obj['secret_util']
    print(f'dry_run: {dry_run}')

    token_ids = vs.get_live_tokens_from_db()
    for token_id in token_ids:
        token = vs.get_token_by_id_from_db(token_id)
        token_id, secret, uuid, other_factors, type = token
        if not dry_run:
            try:
                if other_factors:
                    other_factors = json.loads(other_factors)
                vault = Vault()
                response = vault.create_or_update_secret(token_id, secret, other_factors)
                response.raise_for_status()
            except Exception:
                print('Failed to write token %s to vault' % token_id)
        else:
            print('Token to move: %s' % token_id)


@main.command()
@click.pass_context
@click.argument('token_id')
def clean_pi_by_token_id(ctx, token_id):
    vs = ctx.obj['secret_util']
    secret = vs.get_secret_by_token_id_from_db(token_id)
    PICleaner().remove_pi(secret)


@main.command()
@click.option(
    '--sentence', '-s', type=bool, default=False, required=False, is_flag=True,
    help='Print out the admin list in a sentence.',
)
@click.pass_context
@click.argument('org_name')
def get_org_admins(ctx, sentence, org_name):
    # check if org_name is a username
    github = GitHub()
    response = github.get(f'https://{github_host}/api/v3/users/{org_name}').json()

    # ensure app is installed by getting app github client for user/org
    github_app = GitHubApp().get_github_client(org_name)
    if response['type'] != 'User':
        response = github_app.get(
            f'https://{github_host}/api/v3/orgs/{org_name}/members',
            params={'role': 'admin'},
        )
        # only need logins
        logins = [admin['login'] for admin in response.json()]
    else:
        # the org is a user's personal org
        logins = [org_name]
    if sentence:
        print(
            f'Please obtain a PR approval from an org admin of `{org_name}`.'
            f" We have those listed as:{' @'.join([''] + logins)}",
        )
    else:
        print(logins)


def query_logdna(
    to_time,
    from_time,
    logdna_service_key,
    prefer='tail',
    log_levels='info',
    size=None,
    hosts=None,
    apps=None,
    query=None,
    logdna_api_endpoint='https://api.us-south.logging.cloud.ibm.com/v1/export',
    verbose=False,
):

    payload = {
        'to': to_time,
        'from': from_time,
        'levels': log_levels,
        'prefer': prefer,
    }

    if size is not None:
        payload['size'] = size
    if hosts is not None:
        payload['hosts'] = hosts
    if apps is not None:
        payload['apps'] = apps
    if query is not None:
        payload['query'] = query

    if verbose:
        print(f'params: {payload}')
    resp = requests.get(
        logdna_api_endpoint,
        auth=(logdna_service_key, ''),
        params=payload,
    )
    lines = resp.text.split('\n')
    if verbose:
        print(f'{len(lines)} lines are matched')

    return lines


def _push_to_queue(message, key=None, topic='diff-scan'):
    gd_kafka_conf = ConfUtil.load_kafka_conf()
    kafka_config = {
        'client.id': os.environ['KAFKA_CLIENT_ID'],
        'bootstrap.servers': gd_kafka_conf['brokers_sasl'],
        'security.protocol': 'SASL_SSL',
        'sasl.mechanisms': 'PLAIN',
        'sasl.username': 'token',
        'sasl.password': gd_kafka_conf['api_key'],
        'api.version.request': True,
        'broker.version.fallback': '0.10.2.1',
        'log.connection.close': False,
    }
    print(kafka_config)
    ingest = GDIngest(kafka_config)
    ingest.add_message_to_queue(topic, message=message, key=key)


def rescan(commit, repo, user, branch, public, topic='diff-scan'):
    json_payload = {
        'repoSlug': repo,
        'githubUser': user,
        'commitHash': commit,
        'branchName': branch,
        'repoPublic': public,
    }
    message = json.dumps(json_payload)
    _push_to_queue(message, key=commit, topic=topic)


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out what would be updated',
)
@click.option('-r', '--repo', 'repo', type=str, required=True, help='The repo for leaked token')
@click.option('-c', '--commit-hash', 'commit_hash', type=str, required=True, help='The commit hash contains the token')
@click.option('-b', '--branch', 'branch', type=str, default='refs/heads/master', help='The branch contains the token')
@click.option('-v', '--is-public', 'repo_public', type=bool, default=True, help='Is the repo public.')
@click.option(
    '-p', '--pusher', 'pusher', type=str, default='',
    help='The Github username of pusher. If ommited, will try to locate commiter and author',
)
@click.option(
    '-t', '--topic', 'topic', type=str, default='diff-scan',
    help='The kafka topic to push the message to.',
)
@click.pass_context
def ingest_commit(ctx, dry_run, repo, commit_hash, branch, repo_public, pusher, topic):
    """
    Manually ingest a commit into DSS server. This would trigger an async scan, if there are any
    tokens inside of the commit, they will be recorded.
    """

    print(f'dry_run: {dry_run}')

    # locate pusher through querying the commit info
    github = GitHub()
    resp = github.get(f'https://{github_host}/api/v3/repos/{repo}/commits/{commit_hash}')
    resp_json = json.loads(resp.text)
    if pusher == '':
        if resp_json['committer'] and resp_json['committer']['login']:
            pusher = resp_json['committer']['login']
        elif resp_json['author'] and resp_json['author']['login']:
            pusher = resp_json['author']['login']

    payload_json = {}
    payload_json['commitHash'] = commit_hash
    payload_json['repoSlug'] = repo
    payload_json['githubUser'] = pusher
    payload_json['branchName'] = branch
    payload_json['repoPublic'] = repo_public

    if dry_run:
        print(
            f'Will ingest commit={payload_json["commitHash"]} repo={payload_json["repoSlug"]} '
            f'user={payload_json["githubUser"]} branch={payload_json["branchName"]} '
            f'repoPublic={payload_json["repoPublic"]}',
        )
    else:
        print(
            f'About to ingest commit={payload_json["commitHash"]} repo={payload_json["repoSlug"]} '
            f'user={payload_json["githubUser"]} branch={payload_json["branchName"]} '
            f'repoPublic={payload_json["repoPublic"]}',
        )
        rescan(
            payload_json['commitHash'],
            payload_json['repoSlug'],
            payload_json['githubUser'],
            payload_json['branchName'],
            payload_json['repoPublic'],
            topic,
        )


@main.command()
@click.option(
    '--dry-run', type=bool, default=False, required=False, is_flag=True,
    help='Only print out what would be updated',
)
@click.option(
    '-f', '--from', 'from_time', type=str, default=str(int((time.time() - 600) * 1000)),
    help='from time in milisecond in epoch, like "1568820227437". Default is one hour ago. '
    'On macos, you can use "$(date -j -f "%a %b %d %T %Z %Y" "Wed Sep 11 00:00:00 EDT 2019" +"%s") "'
    'to generate the epoch time',
)
@click.option(
    '-t', '--to', 'to_time', type=str, default=str(int(time.time() * 1000)),
    help='to time in milisecond in epoch, like "1568820227437". Default is current time. '
    'On macos, you can use "$(date -j -f "%a %b %d %T %Z %Y" "Wed Sep 11 00:00:00 EDT 2019" +"%s") "'
    'to generate the epoch time',
)
@click.option('-l', '--levels', 'log_levels', type=str, default='info', help='Log level seperated by comma')
@click.option(
    '-s', '--size', 'size', type=str, default='10000',
    help='Number of results to return. Depends on your plan, but generally the max is 10,000.',
)
@click.option(
    '-p', '--prefer', 'prefer', type=str, default='tail',
    help='head or tail. Defaults to tail. If total results was 654 lines, tail would return the '
    'last 100 lines and head would return the first 100 lines.',
)
@click.option(
    '-k', '--logdna_service_key', 'logdna_service_key', required=True, envvar='GD_LOGDNA_SERVICE_KEY',
    help='The logdna service key. Read from environment variable GD_LOGDNA_SERVICE_KEY',
)
@click.pass_context
def backfill(ctx, dry_run, from_time, to_time, log_levels, size, prefer, logdna_service_key):
    """
    Back fill tokens by searching log from logdna.
    """

    print(f'dry_run: {dry_run}')

    verified_lines = query_logdna(
        to_time,
        from_time,
        logdna_service_key,
        log_levels=log_levels,
        size=size,
        apps='scan-worker',
        query='\'"is_verified": true\'',
        verbose=True,
    )

    # Format for hash_secret_commit_dict below
    #
    # {
    #   "hash_secret1": set("commit1_1", "commit1_2"),
    #   "hash_secret2": set("commit2_1", "commit2_2"),
    # }
    #
    hash_secret_commit_dict = {}

    for line in verified_lines:
        match_commit = re.search(r'.*?scan results for commit ([0-9a-f]{40})', line)
        if match_commit and match_commit.groups():
            commit = match_commit.group(1)
        else:
            continue

        match_hash = re.findall(r'hashed_secret":"([0-9a-f]{40})".*?"verified_result":true', line)
        # print(f'match_hash={match_hash}')
        if not match_hash:
            continue

        for each_hash in match_hash:
            if not hash_secret_commit_dict.get(each_hash):
                hash_secret_commit_dict[each_hash] = set()
            hash_secret_commit_dict[each_hash].add(commit)

    print(f'There are {len(hash_secret_commit_dict.keys())} unique keys')

    for key, value in hash_secret_commit_dict.items():
        # look for other rescan required info based on commit

        # print(f'key={key} value={value}')
        commit = value.pop()
        commit_lines = query_logdna(
            to_time,
            from_time,
            logdna_service_key,
            log_levels=log_levels,
            size=4,  # just need few lines to parse the info
            apps='scan-worker',
            query=f'"Message consumed" {commit}',
        )

        for line in commit_lines:
            try:
                line_json = json.loads(line)
            except Exception:
                continue

            if dry_run:
                print(
                    f'Will rescan commit={line_json["commitHash"]} repo={line_json["repoSlug"]} '
                    f'user={line_json["githubUser"]} branch={line_json["branchName"]} '
                    f'repoPublic={line_json["repoPublic"]}',
                )
            else:
                print(
                    f'About to rescan commit={line_json["commitHash"]} repo={line_json["repoSlug"]} '
                    f'user={line_json["githubUser"]} branch={line_json["branchName"]} '
                    f'repoPublic={line_json["repoPublic"]}',
                )
                rescan(
                    line_json['commitHash'],
                    line_json['repoSlug'],
                    line_json['githubUser'],
                    line_json['branchName'],
                    line_json['repoPublic'],
                )

            # quit on first match since we just need these info once
            break


@main.command()
def get_dss_configs():
    """
    Obtain org admin and security focal for all dss_config.
    This command can take long time to finish, at the scale of 20 minutes.
    """
    # obtain a generic github client
    github = GitHub()
    org_set_controller = OrgSetController()
    orgs_dict = org_set_controller.org_mappings
    # outputs following format
    # email=user@mail_server.domain org_name=abc org_type=User role=org_admin
    # email=user@mail_server.domain org_name=abc org_type=Organization role=org_admin
    # email=user@mail_server.domain org_name=abc org_type=Organization role=security_focal
    for org_name, org_dict in orgs_dict.items():
        try:
            response = github.get(f'https://{github_host}/api/v3/users/{org_name}').json()
        except Exception:
            print('error: fail to query user %s' % org_name)
            continue
        org_type = response['type']
        # output security focal
        for security_focal_email in org_dict['security-focal-emails']:
            print(
                'email=%s org_name=%s org_type=%s role=%s' %
                (security_focal_email, org_name, org_type, 'security_focal'),
            )
        # output org admins
        if response['type'] == 'User':
            # the org is a user's personal org
            print('email=%s org_name=%s org_type=%s role=%s' % (response['email'], org_name, org_type, 'org_admin'))
        else:
            try:
                github_app = GitHubApp().get_github_client(org_name)
            except Exception:
                print('error: fail to obtain github app client for %s' % org_name)
                continue
            admins_response = github_app.get(
                f'https://{github_host}/api/v3/orgs/{org_name}/members',
                params={'role': 'admin'},
            )
            # we need user URLs to obtain emails
            admin_urls = [admin['url'] for admin in admins_response.json()]
            for admin_url in admin_urls:
                admin_response = github_app.get(admin_url).json()
                print(
                    'email=%s org_name=%s org_type=%s role=%s' %
                    (admin_response['email'], org_name, org_type, 'org_admin'),
                )


if __name__ == '__main__':
    main()
