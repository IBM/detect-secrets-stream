#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import os
import random
import re
import sys

import psycopg2
import requests

from ..util.conf import ConfUtil

table_def = [
    (
        'token',
        '(token_id serial PRIMARY KEY, '
        # (Encrypted non-deterministic with asymmetric encryption method) The raw token secret
        'token_cred VARCHAR, '
        'token_comment VARCHAR, '
        'token_type VARCHAR NOT NULL, '
        # Deprecated, replaced by token_commit.filename_located
        'filename_located VARCHAR, '
        # Deprecated, replaced by token_commit.linenumber_located
        'linenumber_located VARCHAR, '
        'first_identified TIMESTAMPTZ NOT NULL DEFAULT NOW(), '
        'is_live BOOLEAN, '
        'last_test_date TIMESTAMPTZ, '
        'last_test_success BOOLEAN, '
        # The hash for raw token_cred. It must be unique for different tokens in same token type
        'token_hash VARCHAR NOT NULL, '
        'other_factors VARCHAR, '
        'uuid VARCHAR NOT NULL, '
        'owner_email VARCHAR, '
        'remediation_date TIMESTAMPTZ'
        ')',
    ),
    (
        'token_owner',
        '(owner_email VARCHAR PRIMARY KEY, '
        'owner_bu VARCHAR, '
        'manager_email VARCHAR, '
        'manager_bu VARCHAR, '
        'escalation_mgr_email VARCHAR, '
        'escalation_mgr_bu VARCHAR'
        ')',
    ),
    (
        'token_commit',
        '(token_id INTEGER NOT NULL, '
        # (Encrypted deterministic with symmetric encryption method) Commit hash
        'hash VARCHAR NOT NULL, '
        'repo VARCHAR NOT NULL,'
        # (Encrypted deterministic with symmetric encryption method) code branch
        'branch VARCHAR NOT NULL, '
        # Deprecated, replaced by pusher_username and committer_user
        'commit_username VARCHAR, '
        # Deprecated, replaced by committer_email
        'commit_email VARCHAR, '
        'date_scanned TIMESTAMPTZ, '
        # (Encrypted deterministic with symmetric encryption method) Name of the file which contains token
        'filename_located VARCHAR NOT NULL, '
        # (Encrypted deterministic with symmetric encryption method) Line number of file which contains token
        'linenumber_located VARCHAR NOT NULL, '
        'author_name VARCHAR, '
        'author_email VARCHAR, '
        'pusher_username VARCHAR NOT NULL, '
        'pusher_email VARCHAR, '
        # Deprecated, replaced by commiter_name
        'committer_user VARCHAR, '
        'committer_email VARCHAR, '
        'committer_name VARCHAR, '
        # (Encrypted deterministic with symmetric encryption method) The html URL can locate the leaked token
        'location_url VARCHAR NOT NULL, '
        'commit_id serial PRIMARY KEY, '
        'repo_public BOOLEAN NOT NULL, '
        'uniqueness_hash VARCHAR NOT NULL, '
        'CONSTRAINT unique_leak_hash UNIQUE(uniqueness_hash)'
        ')',
    ),
    (
        'vmt_report',
        '(vuln_id VARCHAR, '
        'token_owner_email VARCHAR, '
        'token_type VARCHAR, '
        'vulnerability VARCHAR, '
        'pusher_email VARCHAR, '
        'committer_email VARCHAR, '
        'author_email VARCHAR, '
        'date_last_tested TIMESTAMPTZ, '
        'date_remediated TIMESTAMPTZ, '
        'security_focals VARCHAR, '
        'repo_public BOOLEAN, '
        'repo_private BOOLEAN)',
    ),
]

user_def = {
    'read_only':
        (
            'GRANT SELECT ON ALL TABLES IN SCHEMA public TO ',
            '',
        ),
    'read_write':
        (
            'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ',
            'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ',
        ),
    'admin':
        (
            'GRANT ALL ON ALL TABLES IN SCHEMA public TO ',
            'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ',
        ),
}


def connect_db():
    """ collect env vars & connect to corpus """
    try:
        db_conf = ConfUtil.load_db_conf()
        # Creds from:
        # https://cloud.ibm.com/services/databases-for-postgresql/crn:v1:bluemix:public:databases-for-postgresql:us-east:a%2f26bb005a5183cf92d5694dd5e93c03c2:9f5cefd3-2130-430b-8e28-bee3a0f8e105::?paneId=credentials
        gd_db_database = db_conf['database']
        gd_db_hostname = db_conf['hostname']
        gd_db_port = db_conf['port']
        gd_db_uid = db_conf['username']
        gd_db_pwd = db_conf['password']

        conn_string = 'host=' + gd_db_hostname + ' port=' + gd_db_port + ' dbname=' + \
            gd_db_database + ' user=' + gd_db_uid + ' password=' + gd_db_pwd
        print(f'Connecting to database\n	-> {gd_db_database} on {gd_db_hostname}:{gd_db_port}')
        __conn = psycopg2.connect(conn_string)
        print('Connected!\n')
        return(__conn)
    except Exception as e:
        print('Unable to connect to the database.')
        raise e


def disconnect_db(conn):
    """ disconnect from the database """
    try:
        conn.close()
        print('\nSuccess disconnecting')
    except Exception as e:
        print('Fail to disconnect')
        raise e


def vaildate_name(name):
    '''
    Make sure the incoming name only contains alphanumeric characters or underscore.
    No whitespace or oherr special characters are allowed.

    Return True if matches the rule, otherwise return False
    '''
    if name and re.match('^\\w+$', name):
        return True
    else:
        return False


def create_id(conn, user_id, user_auth_string1, user_auth_string2):
    """ create a connecting corpus PSQL ID with the associated rights: 'read_only', 'write_rows', 'admin' """

    if '-' in user_id:
        print(f"User: {user_id} not created - IDs cannot contain '-', use '_' instead.")
        return(1)

    db_conf = ConfUtil.load_db_conf()
    gd_db_database = db_conf['database']

    if not vaildate_name(user_id):
        print(f'Username={user_id} is invalid')
        return 1

    if not vaildate_name(gd_db_database):
        print(f'Database name={gd_db_database} is invalid')
        return 1

    try:
        sql_lines = [
            'CREATE USER ' + user_id + '; ',
            'GRANT CONNECT ON DATABASE ' + gd_db_database + ' TO ' + user_id + '; ',
            user_auth_string1 + user_id + '; ',
            user_auth_string2 + user_id + '; ',
        ]
        for cs in sql_lines:
            if cs != (user_id + '; '):
                cur = conn.cursor()
                print(f'Executing: {cs}')
                cur.execute(cs)
                conn.commit()
                cur.close()
        print(f'Created {user_id} user')

        return(0)
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        print(f"User {user_id} won't create!")
        return(error)


def drop_id(conn, user_id):
    """ delete corpus PSQL ID & associated KP Key """

    db_conf = ConfUtil.load_db_conf()
    gd_db_database = db_conf['database']

    if not vaildate_name(user_id):
        print(f'Username={user_id} is invalid')
        return 1

    if not vaildate_name(gd_db_database):
        print(f'Database name={gd_db_database} is invalid')
        return 1

    try:
        sql_lines = [
            'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ' + user_id + '; ',
            'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ' + user_id + '; ',
            'REVOKE ALL PRIVILEGES ON DATABASE ' +
            gd_db_database + ' FROM ' + user_id + '; ',
            'DROP USER ' + user_id + '; ',
        ]
        for cs in sql_lines:
            cur = conn.cursor()
            print(f'Executing: {cs}')
            cur.execute(cs)
            conn.commit()
            cur.close()
        print(f'Dropped {user_id} database user')

        if kp_delete_gd_user_key(user_id) != 1:
            print(f'Deleted {user_id} KP key')
        else:
            print(f'Unable to delete {user_id} KP key')

    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        print(f"User {user_id} won't delete!")
        return(error)


# from https://cloud.ibm.com/apidocs/key-protect?code=python
def kp_create_gd_user_key(user_id):
    """ creates Key Protect key and returns its ID or 1 if it fails """
    try:
        gd_kp_region = os.environ['GD_KP_REGION']
        gd_kp_service_instance = os.environ['GD_KP_SERVICE_INSTANCE']
        gd_kp_token = os.environ['GD_KP_TOKEN']

        url = 'https://' + gd_kp_region + '.kms.cloud.ibm.com/api/v2/keys'

        headers = {
            'authorization': 'Bearer ' + gd_kp_token,
            'bluemix-instance': gd_kp_service_instance,
            'accept': 'application/vnd.ibm.collection+json',
        }
        data = {
            'metadata': {
                'collectionType': 'application/vnd.ibm.kms.key+json',
                'collectionTotal': 1,
            },
            'resources': [
                {
                    'type': 'application/vnd.ibm.kms.key+json',
                    'name': user_id,
                    'description': 'gb_db access key generated by gd_db_tools',
                    'extractable': True,
                },
            ],
        }

        print(f'Creating key {user_id} with Key Protect API')
        results_raw = requests.request('POST', url, headers=headers, json=data)
        results = json.loads(results_raw.text)
        rv = results_raw.status_code

        if rv == 201:
            print(f'Successfully created key {user_id}')
            return(((results['resources'])[0])['id'])
        else:
            return(1)

    except (requests.exceptions.RequestException, ConnectionResetError) as error:
        print('KP REST request error:', error)
        print(f'Unable to create key: {user_id}')
        return(error)


# from https://cloud.ibm.com/apidocs/key-protect?code=python
def kp_delete_gd_user_key(user_id):
    """ delete key protect key associated with the user_id name """

    try:
        gd_kp_region = os.environ['GD_KP_REGION']
        gd_kp_service_instance = os.environ['GD_KP_SERVICE_INSTANCE']
        gd_kp_token = os.environ['GD_KP_TOKEN']

        url = 'https://' + gd_kp_region + '.kms.cloud.ibm.com/api/v2/keys'

        headers = {
            'authorization': 'Bearer ' + gd_kp_token,
            'bluemix-instance': gd_kp_service_instance,
            'accept': 'application/vnd.ibm.collection+json',
        }

        print('Pulling list of keys from Key Protect API')
        results = json.loads(
            requests.request(
                'GET', url, headers=headers,
            ).text,
        )
        keys = results['resources']
        key_id = 0
        for k in keys:
            print(f"Key name: {k['name']} ID: {k['id']}")
            if k['name'] == user_id:
                key_id = k['id']
        if key_id != 0:
            print(f'Deleting key ID: {key_id}')
        else:
            print(f'Key: {user_id} not found')
            return(1)
        url = 'https://' + gd_kp_region + '.kms.cloud.ibm.com/api/v2/keys/' + key_id
        rc = requests.request('DELETE', url, headers=headers)
        if rc.status_code == 204:
            print(f'Key: {user_id}, ID: {key_id} successfully deleted')
        else:
            print(f'Key: {user_id}, ID: {key_id} *NOT* deleted')
        return(rc.status_code)
    except (requests.exceptions.RequestException, ConnectionResetError) as error:
        print('KP REST request error:', error)
        print(f'Unable to delete key for {user_id}')
        return(error)


# from https://cloud.ibm.com/apidocs/key-protect?code=python
def kp_get_gd_user_key(user_id):
    """ get Key Protect key returns key's value """
    try:
        gd_kp_region = os.environ['GD_KP_REGION']
        gd_kp_service_instance = os.environ['GD_KP_SERVICE_INSTANCE']
        gd_kp_token = os.environ['GD_KP_TOKEN']

        url = 'https://' + gd_kp_region + '.kms.cloud.ibm.com/api/v2/keys'

        headers = {
            'authorization': 'Bearer ' + gd_kp_token,
            'bluemix-instance': gd_kp_service_instance,
            'accept': 'application/vnd.ibm.collection+json',
        }
        print('Pulling list of keys from Key Protect API')
        results = json.loads(
            requests.request(
                'GET', url, headers=headers,
            ).text,
        )
        keys = results['resources']

        for k in keys:
            print(f"Key name: {k['name']} ID: {k['id']}")
            if k['name'] == user_id:
                key_id = k['id']
        print(f"Pulling key ID: {key_id}'s details")
        url = 'https://' + gd_kp_region + '.kms.cloud.ibm.com/api/v2/keys/' + key_id
        results_raw = requests.request('GET', url, headers=headers)
        results = json.loads(results_raw.text)
        rv = results_raw.status_code
        print(rv)
        if rv == 200:
            return(((results['resources'])[0])['payload'])
        else:
            return(1)

    except (requests.exceptions.RequestException, ConnectionResetError) as error:
        print('KP REST request error:', error)
        print(f'Unable to retrieve key for {user_id}')
        return(error)


def create_table(conn, table_name, table_create_string):
    """ create table"""
    if not vaildate_name(table_name):
        print(f'Table name={table_name} is invalid')
        return 1

    try:
        cur = conn.cursor()
        cur_string = 'CREATE TABLE ' + table_name + ' ' + table_create_string + ';'
        print(f'Table creation with: {cur_string}')
        cur.execute(cur_string)
        print(f'Created {table_name} table')
        conn.commit()
        cur.close()
        return()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        print(f"{table_name} table won't create!")
        return(error)


def create_tables(conn):
    for table_name, table_create_string in table_def:
        print(
            f'TABLE NAME: {table_name}\nCREATE STRING:\n{table_create_string}\n\n',
        )
        create_table(conn, table_name, table_create_string)


def get_token_id_by_type_hash(conn, token_type: str, token_hash: str, only_live=False):
    """ select token id by token_type and token_hash """
    result = []
    try:
        cur = conn.cursor()
        sql = 'select token_id from token where token_type = %s and token_hash = %s'
        if only_live:
            sql += ' and is_live is true'
        cur.execute(sql, (token_type, token_hash))
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def add_token_row(
    conn, token_cred, token_type, token_comment, other_factors, uuid, is_live,
    token_hash='', owner_email='', remediation_date=None,
):
    """ add token row """
    cur = conn.cursor()

    # SQL statement errors on writing to the DB:
    # SQL error: column "x" of relation "token" does not exist        - beware of rogue blank characters in column defs
    # SQL error: not all arguments converted during string formatting - too few  'VALUES'
    # SQL error: tuple index out of range                             - too many 'VALUES'

    sql = """INSERT INTO token
    (
        token_cred,
        token_type,
        token_comment,
        token_hash,
        other_factors,
        uuid,
        is_live,
        owner_email,
        remediation_date
        )
             VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING token_id;"""
    try:
        cur.execute(
            sql, (
                token_cred,
                token_type,
                token_comment,
                token_hash,
                other_factors,
                uuid,
                is_live,
                owner_email,
                remediation_date,
            ),
        )
        token_id = cur.fetchone()[0]
        print(f'Token inserted {token_cred}, ID:{token_id}')
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        return(error)
    return token_id


def update_other_factors_by_token_id(
    conn,
    token_id,
    other_factors,
):
    cur = conn.cursor()

    print('updating other factors')

    sql = '''update token set
    other_factors = %s
    where token_id = %s'''
    try:
        cur.execute(
            sql, (
                other_factors,
                token_id,
            ),
        )
        print(f'Token updated, ID:{token_id}')
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error
    return token_id


def update_token_by_id(
    conn,
    token_id,
    token_cred,
    token_comment,
    token_type,
    first_identified,
    is_live,
    last_test_date,
    last_test_success,
    other_factors,
    uuid,
    token_hash,
    owner_email,
    remediation_date,
):
    """ add token row """
    cur = conn.cursor()

    print(f'Updating token row by token_id {token_id}')
    sql = '''update token set
    token_cred = %s,
    token_comment = %s,
    token_type = %s,
    first_identified = %s,
    is_live = %s,
    last_test_date = %s,
    last_test_success = %s,
    token_hash = %s,
    other_factors = %s,
    uuid = %s,
    owner_email = %s,
    remediation_date = %s
    where token_id = %s'''
    try:
        cur.execute(
            sql, (
                token_cred,
                token_comment,
                token_type,
                first_identified,
                is_live,
                last_test_date,
                last_test_success,
                token_hash,
                other_factors,
                uuid,
                owner_email,
                remediation_date,
                token_id,
            ),
        )
        print(f'Token updated, ID:{token_id}')
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error
    return token_id


def add_commit_row(
    conn, token_id, hash, repo, branch, filename_located, linenumber_located,
    author_name, author_email, pusher_username, pusher_email, committer_name,
    committer_email, location_url, repo_public, uniqueness_hash,
):
    """ add commit row """
    cur = conn.cursor()

    sql = """INSERT INTO token_commit
    (token_id, hash, repo, branch, filename_located, linenumber_located,
     author_name, author_email, pusher_username, pusher_email, committer_name,
     committer_email, location_url, repo_public, uniqueness_hash)
    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING commit_id;"""
    try:
        cur.execute(
            sql, (
                token_id, hash, repo, branch, filename_located, linenumber_located,
                author_name, author_email, pusher_username, pusher_email, committer_name,
                committer_email, location_url, repo_public, uniqueness_hash,
            ),
        )
        commit_id = cur.fetchone()[0]
        print(f'Commit row inserted for token_id: {token_id}, commit_id: {commit_id}')
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error
    return commit_id


def get_token_count_by_type(conn):
    result = []
    try:
        cur = conn.cursor()
        print('Getting tokens counts')
        cur.execute(
            '''select tkn.token_type, tkn.is_live, tkn.repo_public, count(*)
                from (select t.token_type, t.is_live, tc.repo_public from token as t
                join token_commit as tc on t.token_id = tc.token_id group by t.token_type, t.is_live,
                tc.repo_public, t.token_id) as tkn
                group by tkn.token_type, tkn.is_live, tkn.repo_public;''',
        )
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            print(row)
            result.append(row)
            row = cur.fetchone()
        cur.close()
        print('\n')
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def _get_commit_encrypted_column(conn, commit_id=None):
    result = []
    try:
        cur = conn.cursor()
        sql = '''select
        commit_id,
        hash,
        branch,
        filename_located,
        linenumber_located,
        location_url
        from token_commit'''

        if commit_id is None:
            print('Getting encrypted field from commit for all commits')
            cur.execute(sql)
        else:
            sql = sql + ''' where commit_id = %s'''
            cur.execute(sql, (commit_id,))
            print(f'Getting encrypted field from commit by id {commit_id}')

        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_commit_encrypted_columns_by_id(conn, commit_id):
    return _get_commit_encrypted_column(conn, commit_id)


def get_commit_encrypted_columns_all(conn):
    return _get_commit_encrypted_column(conn)


def update_commit_encrypted_columns_by_id(
    conn,
    commit_id,
    encrypted_commit_hash,
    encrypted_branch_name,
    encrypted_filename,
    encrypted_linenumber,
    encrypted_location_url,
):
    """
    Update encrypted columnes in commit table based on commit id
    """
    try:
        cur = conn.cursor()
        print(f'Updating commit encrypted columns by commit_id {commit_id}')
        sql = '''update token_commit set
        hash = %s,
        branch = %s,
        filename_located = %s,
        linenumber_located = %s,
        location_url = %s
        where commit_id = %s'''
        cur.execute(
            sql, (
                encrypted_commit_hash,
                encrypted_branch_name,
                encrypted_filename,
                encrypted_linenumber,
                encrypted_location_url,
                commit_id,
            ),
        )
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def update_token_hash_by_id(conn, token_id, token_hash):
    """
    Update token hash based on token id
    """
    try:
        cur = conn.cursor()
        print('Updating token_hash by token_id')
        sql = 'update token set token_hash = %s where token_id = %s'
        cur.execute(sql, (token_hash, token_id))
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def update_token_uuid_by_id(conn, token_id, uuid):
    """
    Update token uuid based on token id
    """
    try:
        cur = conn.cursor()
        print('Updating uuid by token_id')
        sql = 'update token set uuid = %s where token_id = %s'
        cur.execute(sql, (uuid, token_id))
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def update_commit_by_commit_id(
    conn, commit_id, commit_hash, repo_slug, branch_name, location_url,
    pusher_username, pusher_email, author_name,
    author_email, committer_name, committer_email, repo_public, uniqueness_hash,
    filename, linenumber, token_id,
):
    """
    Update hash, repo, branch, location url, pusher username,
    pusher email, author name, author_email, committer user, commit email,
    repo public
    based on commit id.
    """
    try:
        cur = conn.cursor()
        print(f'Updating commit by commit_id. commit_id={commit_id} token_id={token_id}')
        sql = '''update token_commit set hash=%s, repo=%s, branch=%s,
        location_url=%s, pusher_username=%s, pusher_email=%s,
        author_name=%s, author_email=%s, committer_name=%s,
        committer_email=%s, repo_public=%s, uniqueness_hash=%s,
        filename_located=%s, linenumber_located=%s, token_id=%s where commit_id = %s'''
        cur.execute(
            sql, (
                commit_hash, repo_slug, branch_name, location_url,
                pusher_username, pusher_email, author_name, author_email,
                committer_name, committer_email, repo_public,
                uniqueness_hash, filename, linenumber, token_id, commit_id,
            ),
        )
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def update_location_url_by_hash_and_repo(
    conn, commit_hash, repo, location_url,
):
    try:
        cur = conn.cursor()
        print('Updating location_url by hash and repo')
        sql = '''update token_commit set location_url = %s where hash = %s and
        repo = %s'''
        cur.execute(
            sql, (
                location_url, commit_hash, repo,
            ),
        )
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def get_tokens_by_type(conn, token_type):
    result = []
    try:
        cur = conn.cursor()
        print('Getting tokens by type')
        sql = '''select
        token_id,
        decode(substring(token_cred from 3), 'hex'),
        uuid,
        date(first_identified) as first_identified_date,
        decode(substring(other_factors from 3), 'hex'),
        is_live
        from token where token_type = %s order by first_identified_date'''
        cur.execute(sql, (token_type,))
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            # print(row)
            result.append(row)
            row = cur.fetchone()
        cur.close()
        print('\n')
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_token_by_id_limited(conn, token_id):
    result = []
    try:
        cur = conn.cursor()
        print(f'Getting token by id {token_id}')
        sql = '''select token_id,
        decode(substring(token_cred from 3), 'hex'),
        uuid,
        decode(substring(other_factors from 3), 'hex'),
        token_type
        from token where token_id = %s'''
        cur.execute(sql, (token_id,))
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_live_tokens(conn):
    result = []
    try:
        cur = conn.cursor()
        print('Getting all live tokens')
        sql = '''select
        token_id
        from token where is_live is not false'''
        cur.execute(sql)
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_remediated_tokens(conn):
    result = []
    try:
        cur = conn.cursor()
        print('Getting all live tokens')
        sql = '''select
        token_id
        from token where is_live is false'''
        cur.execute(sql)
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_all_tokens(conn):
    result = []
    try:
        cur = conn.cursor()
        print('Getting all live tokens')
        sql = '''select
        token_id
        from token'''
        cur.execute(sql)
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_commits_by_token_id(conn, token_id):
    result = []
    try:
        cur = conn.cursor()
        print(f'Getting commit by token_id {token_id}')
        sql = '''select
        commit_id,
        decode(substring(hash from 3), 'hex'),
        repo,
        decode(substring(branch from 3), 'hex'),
        decode(substring(location_url from 3), 'hex'),
        author_name,
        author_email,
        pusher_username,
        pusher_email,
        committer_name,
        committer_email,
        repo_public,
        uniqueness_hash,
        decode(substring(filename_located from 3), 'hex'),
        decode(substring(linenumber_located from 3), 'hex'),
        token_id
        from token_commit where token_id = %s'''
        cur.execute(sql, (token_id,))
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_token_by_uuid(conn, token_uuid):
    result = []
    try:
        cur = conn.cursor()
        print(f'Getting token by id {token_uuid}')
        sql = '''select
        token_id,
        decode(substring(token_cred from 3), 'hex'),
        token_comment,
        token_type,
        first_identified,
        is_live,
        last_test_date,
        last_test_success,
        token_hash,
        decode(substring(other_factors from 3), 'hex'),
        uuid,
        owner_email,
        remediation_date
        from token where uuid = %s'''
        cur.execute(sql, (token_uuid,))
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def get_token_by_id(conn, token_id):
    result = []
    try:
        cur = conn.cursor()
        print(f'Getting token by id {token_id}')
        sql = '''select
        token_id,
        decode(substring(token_cred from 3), 'hex'),
        token_comment,
        token_type,
        first_identified,
        is_live,
        last_test_date,
        last_test_success,
        token_hash,
        decode(substring(other_factors from 3), 'hex'),
        uuid,
        owner_email,
        remediation_date
        from token where token_id = %s'''
        cur.execute(sql, (token_id,))
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def generate_report_live_token(conn):
    result = []
    try:
        cur = conn.cursor()
        sql = ''' select
                t.token_id,
                t.uuid,
                t.token_cred,
                t.owner_email,
                c.location_url,
                c.repo,
                c.filename_located,
                c.linenumber_located,
                c.hash,
                t.first_identified,
                t.other_factors,
                t.token_type,
                c.pusher_email,
                c.committer_email,
                c.author_email,
                t.last_test_date,
                t.remediation_date,
                t.is_live,
                c.repo_public,
                NOT c.repo_public
                from token_commit as c,
                    (select distinct on (token_type, token_hash)
                    token_type,
                    token_hash,
                    token_id,
                    uuid,
                    owner_email,
                    first_identified,
                    last_test_date,
                    other_factors,
                    token_cred,
                    remediation_date,
                    is_live
                    from token
                    where
                        token_type <> 'Test Secret'
                        and is_live is true
                    order by token_type, token_hash, token_id) as t
                where c.token_id = t.token_id
                order by c.commit_id asc;
        '''
        cur.execute(sql)
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def generate_report_recently_remediated(conn):
    result = []
    try:
        cur = conn.cursor()
        sql = ''' select
                t.token_id,
                t.uuid,
                t.token_cred,
                t.owner_email,
                c.location_url,
                c.repo,
                c.filename_located,
                c.linenumber_located,
                c.hash,
                t.first_identified,
                t.other_factors,
                t.token_type,
                c.pusher_email,
                c.committer_email,
                c.author_email,
                t.last_test_date,
                t.remediation_date,
                t.is_live,
                c.repo_public,
                NOT c.repo_public
                from token_commit as c,
                    (select distinct on (token_type, token_hash)
                    token_type,
                    token_hash,
                    token_id,
                    uuid,
                    owner_email,
                    first_identified,
                    last_test_date,
                    other_factors,
                    token_cred,
                    remediation_date,
                    is_live
                    from token
                    where
                        token_type <> 'Test Secret'
                        and is_live is false
                        and remediation_date > now() - interval '1 week'
                    order by token_type, token_hash, token_id) as t
                where c.token_id = t.token_id
                order by c.commit_id asc;
        '''
        cur.execute(sql)
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def truncate_vmt_report(conn):
    try:
        cur = conn.cursor()
        sql = 'TRUNCATE TABLE vmt_report'
        cur.execute(sql)
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def write_vmt_report(
    conn,
    vuln_id,
    token_owner_email,
    token_type,
    vulnerability,
    pusher_email,
    committer_email,
    author_email,
    date_last_tested,
    date_remediated,
    security_focals,
    repo_public,
    repo_private,
):
    try:
        sql = """INSERT INTO vmt_report(
            vuln_id,
            token_owner_email,
            token_type,
            vulnerability,
            pusher_email,
            committer_email,
            author_email,
            date_last_tested,
            date_remediated,
            security_focals,
            repo_public,
            repo_private
        ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""
        cur = conn.cursor()
        cur.execute(
            sql, (
                vuln_id,
                token_owner_email,
                token_type,
                vulnerability,
                pusher_email,
                committer_email,
                author_email,
                date_last_tested,
                date_remediated,
                security_focals,
                repo_public,
                repo_private,
            ),
        )
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error


def get_commits(conn, visibility='all'):
    result = []
    try:
        cur = conn.cursor()
        sql = '''select
        commit_id,
        decode(substring(hash from 3), 'hex'),
        repo,
        decode(substring(branch from 3), 'hex'),
        decode(substring(location_url from 3), 'hex'),
        author_name,
        author_email,
        pusher_username,
        pusher_email,
        committer_name,
        committer_email,
        repo_public,
        uniqueness_hash,
        decode(substring(filename_located from 3), 'hex'),
        decode(substring(linenumber_located from 3), 'hex'),
        token_id
        from token_commit'''
        if visibility == 'private':
            sql += ''' where repo_public is false'''
        elif visibility == 'public':
            sql += ''' where repo_public is true'''
        cur.execute(sql)
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            result.append(row)
            row = cur.fetchone()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        raise error

    return result


def list_rows(conn, table_name):
    """ list rows from table """
    if not vaildate_name(table_name):
        print(f'Table name={table_name} is invalid')
        return 1

    try:
        cur = conn.cursor()
        print('Listing rows from: ', table_name)
        cur.execute('SELECT * FROM ' + table_name)
        print(f'Number of rows: {cur.rowcount}')
        row = cur.fetchone()
        while row is not None:
            print(row)
            row = cur.fetchone()
        cur.close()
        print('\n')
    except (Exception, psycopg2.DatabaseError) as error:
        print('SQL error:', error)
        return(error)


def tear_down_table(conn, table_name):
    """ destroy table"""
    if not vaildate_name(table_name):
        print(f'Table name={table_name} is invalid')
        return 1

    destroying_query = 'Destroy ' + table_name + '?? (YES/no) '
    if input(destroying_query) == 'YES':
        print('Dropping table')

        try:
            cur = conn.cursor()
            sql = 'DROP TABLE ' + table_name + ';'
            print(sql)
            cur.execute(sql)
            conn.commit()
            cur.close()
            print('Table successfully dropped')
        except (Exception, psycopg2.DatabaseError) as error:
            print('SQL error:', error)
            return(error)

    else:
        print("Ok I won't then")
    return()


def main():
    """ main orchestration """

    try:
        conn = connect_db()
        opt = sys.argv
        if '--create-tables' in opt or '-ct' in opt:
            create_tables(conn)
        elif '--create-user' in opt or '-cu' in opt:
            user, rights = opt[2].split(':')
            print(f'Creating user: {user} with rights: {rights}')
            auth_str1, auth_str2 = user_def[rights]
            create_id(conn, user, auth_str1, auth_str2)
        elif '--delete-key' in opt or '-dk' in opt:
            kp_delete_gd_user_key(opt[2])
        elif '--read-key' in opt or '-rk' in opt:
            if '--display_key' in opt:
                print(f"{opt[2]}'s key: {kp_get_gd_user_key(opt[2])}")
        elif '--drop-user' in opt or '-du' in opt:
            drop_id(conn, opt[2])
        elif '--test-token-add' in opt or '-t' in opt:
            add_token_row(
                conn, '%030x' % random.randrange(
                    16**40,
                ), 'spurious type', 'fake token',
            )
        elif '--list-rows' in opt or '-ls' in opt:
            for table_name, _ in table_def:
                list_rows(conn, table_name)
        elif '--tear-down-tables' in opt:
            for table_name, table_create_string in table_def:
                tear_down_table(conn, table_name)
        else:
            print('Only connection test.')
            print('Usage:')
            print('python gd_db_tools.py [-ct] | [-cu <user_id>:read_only|read_write|admin] | [-du <user_id>] | [-dk <key>] [-t] | [-ls]')  # noqa E501
            print('-ct,    --create-tables        create all tables\n \
                -cu,    --create-user          create PSQL user & assign KP access key (invisible to you)\n \
                -du,    --drop-user            drop PSQL user & associated KP key \n \
                -dk,    --delete-key           delete Key Protect key \n \
                -t,     --test-token-add       add test token\n \
                -ls,    --list-rows            lists all rows in all tables\n \
                        --tear-down-tables     destroys all tables - after confirmation')

        disconnect_db(conn)
        print('\nSuccess exiting')
        return(True)
    except Exception:
        print('\nOrchestration error exiting')
        return(False)


if __name__ == '__main__':
    main()
