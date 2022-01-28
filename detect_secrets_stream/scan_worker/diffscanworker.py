"""
 Copyright 2015-2018 IBM

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 Licensed Materials - Property of IBM
 © Copyright IBM Corp. 2015-2018
"""
import asyncio
import json
import logging
import subprocess

import psycopg2
from confluent_kafka import Consumer
from confluent_kafka import Producer
from jaeger_client import Config
from jaeger_client.metrics.prometheus import PrometheusMetricsFactory
from opentracing.propagation import Format
from requests.exceptions import HTTPError

from ..bp_lookup.bp_lookup import GHElookup
from ..github_client.github import GitHub
from ..github_client.github_app import GitHubApp
from ..github_client.installation_id_request_exception import InstallationIDRequestException
from ..scan_worker.sanitizer import Sanitizer
from ..secret_corpus_db.data_cleanliness_exception import DataCleanlinessException
from ..secret_corpus_db.gd_db_tools import add_commit_row
from ..secret_corpus_db.gd_db_tools import add_token_row
from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import get_token_id_by_type_hash
from ..secret_corpus_db.vault import Vault
from ..util.conf import ConfUtil
from .commit import Commit
from .commitparser import CommitParser
from .diffextractor import DiffExtractor
from .secret import Secret
# from .wds_experiments import WDSExperiments


class DiffScanWorker(object):

    def __init__(
        self, conf, diff_scan_topic, notification_topic, async_sleep_time=2,
    ):
        self.consumer = Consumer(conf)
        self.producer = Producer(conf)
        self.diff_scan_topic = diff_scan_topic
        self.notification_topic = notification_topic
        self.running = True
        self.tracer = self.init_tracer()
        self.diff_filename = './diff.txt'
        self.async_sleep_time = async_sleep_time
        self.logger = logging.getLogger(__name__)
        self.github_host = ConfUtil.load_github_conf()['host']
        self.commit_parser = CommitParser(max_commits_to_pull=25)

        self.github = GitHub()
        self.github_app = GitHubApp()
        self.ghe_lookup = GHElookup(self.logger)

    def stop(self):
        self.running = False

    def get_github_client_for_repo(self, repo_slug, repo_public: str):
        if repo_public == 'false':
            return self.github_app.get_github_client(repo_slug)
        else:
            return self.github

    def init_tracer(self, service_name='detect_secrets'):
        config = Config(
            config={  # usually read from some yaml config
                'sampler': {
                    'type': 'const',
                    'param': 1,
                },
                'logging': True,
            },
            service_name=service_name,
            validate=True,
            metrics_factory=PrometheusMetricsFactory(namespace=service_name),
        )
        return config.initialize_tracer()

    def create_diff_file(self, repo, commit, github):
        """
        Creates a diff file for a given commit on a repo.
        """
        headers = {
            'Accept': 'application/vnd.github.v3.diff',
        }
        try:
            response = github.get(
                url=f'https://{self.github_host}/api/v3/repos/{repo}/commits/{commit}',
                headers=headers,
            )
            # check response status code
            self.logger.info(
                f'GHE API response to diff request for commit {commit}: {response.status_code}',
            )
            # check and print rate limit information
            self.logger.info(
                f"GHE API requests remaining: {response.headers['X-RateLimit-Remaining']}",
            )

            response.raise_for_status()

        except HTTPError as http_err:
            self.logger.error(
                'Diff request to GHE API caused an HTTP error: %s' % http_err, exc_info=1,
            )
            raise http_err
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise e
        else:
            # write diff to file for scanning
            with open(self.diff_filename, 'w') as diff_file:
                diff_file.write(response.text)

    def run_detect_secrets(self, commit, verify=True):
        """
        Runs detect-secrets scan on the diff file.

        Returns: string, a json string of the detect-secrets scan output
        """

        bash_command = (
            'detect-secrets scan --db2-scan --no-keyword-scan --no-private-key-scan '
            '--no-basic-auth-scan --no-twilio-key-scan --no-base64-string-scan --no-hex-string-scan '
            f'--no-jwt-scan --output-raw --ghe-instance {self.github_host} {self.diff_filename}'
        )
        # for test code...
        if not verify:
            bash_command = (
                'detect-secrets scan --no-verify --db2-scan --no-keyword-scan '
                '--no-private-key-scan --no-basic-auth-scan --no-twilio-key-scan '
                '--no-base64-string-scan --no-hex-string-scan --no-jwt-scan '
                f'--output-raw --ghe-instance {self.github_host} {self.diff_filename}'
            )
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        results = output.decode('utf-8')

        # sanitize raw secret before printing to logs
        try:
            results = Sanitizer.use_old_ghe_secret_type(results)
            results_dict = json.loads(results)
            for filename in results_dict['results']:
                for secret in results_dict['results'][filename]:
                    secret['secret'] = '[secure]'
            self.logger.info(
                'detect-secrets scan results for commit %s: %s' %
                (commit, json.dumps(results_dict)),
            )
            return results
        except Exception as e:
            self.logger.error(
                'Error sanitizing detect-secrets output: %s' % e, exc_info=1,
            )

    def validate_secrets(self, detect_secrets_output, commit):
        """
        Validates potential secrets.

        Accepts: string, a json string of the detect-secrets scan output
        Returns: a list of validated Secret objects
        """

        scan_results = json.loads(detect_secrets_output)

        validated_secrets = []
        for filename in scan_results['results']:
            for result in scan_results['results'][filename]:
                secret_type = result['type']
                secret_found = result['secret']
                diff_file_linenumber = result['line_number']
                other_factors = None
                if 'other_factors' in result:
                    other_factors = result['other_factors']
                is_verified = None
                if 'is_verified' in result:
                    is_verified = result['is_verified']
                if is_verified:
                    secret = Secret(secret_found, secret_type)
                    secret.live = True
                    secret.diff_file_linenumber = diff_file_linenumber
                    if other_factors:
                        secret.other_factors = other_factors
                    validated_secrets.append(secret)

        if not validated_secrets:
            self.logger.info('No validatated secrets for commit %s.' % commit)
        return validated_secrets

    def extract_filename_linenumber(self, validated_secrets):
        """
        For validated secrets, extracts the original filename and linenumber
        and adds it to the metadata for the secret.

        Accepts: a list of validated Secret objects
            a Commit object
        Returns: a list of validated Secret objects with their filename and linenumber fields set
        """
        if validated_secrets:
            diffextractor = DiffExtractor(
                self.diff_filename,
            )

            diff_file_linenumbers = [
                secret.diff_file_linenumber for secret in validated_secrets
            ]
            results = diffextractor.extract_filename_linenumbers(
                diff_file_linenumbers,
            )

            for secret in validated_secrets:
                secret.filename = results[secret.diff_file_linenumber]['filename']
                secret.linenumber = results[secret.diff_file_linenumber]['linenumber']

        return validated_secrets

    def lookup_additional_github_info(self, pusher_username, repo, commit, repo_public: str):
        """ Looks up pusher email, author name, author email,
        committer name, committer email from GitHub given
        the pusher username, repo slug, and commit hash. """
        ghe_lookup = GHElookup(self.get_github_client_for_repo(repo, repo_public))
        pusher_email = ghe_lookup.ghe_email_lookup(pusher_username)
        author_name, author_email, committer_name, committer_email = ghe_lookup.ghe_author_committer_lookup(
            repo, commit,
        )
        return (pusher_email, author_name, author_email, committer_name, committer_email)

    def write_to_vault(self, secret: Secret):
        """
        Writes raw secret and other factors to vault.

        Accepts: secret, a Secret object.
        Throws: HTTPError if write to vault fails.
            DataCleanlinessException is secret not properly populated for write.
        """
        if not secret.is_ready_for_vault_insert():
            self.logger.error('Attempt to write incomplete Secret object to vault.')
            raise DataCleanlinessException('Attempt to write incomplete Secret object to vault.')
        vault = Vault()
        response = vault.create_or_update_secret(secret.id, secret.secret, secret.other_factors)
        response.raise_for_status()

    def insert_token_to_db(self, db_conn, secret: Secret) -> str:
        """
        Writes secret token into db. It would run deduplication to make sure same token does not store
        twice in the DB.

        Accepts: secret, a Secret objects
        Returns: token_id for the same token if it existed in the database, or token_id for
                the newly written entry.
        """
        token_ids = get_token_id_by_type_hash(
            db_conn, secret.secret_type, secret.hashed_secret,
        )

        if token_ids:
            token_id = token_ids[0]
            if isinstance(token_id, tuple):
                token_id = token_id[0]
            return token_id

        token_id = add_token_row(
            db_conn, None, secret.secret_type, 'beta', None, secret.uuid,
            secret.live, secret.hashed_secret, secret.owner_email,
        )
        return token_id

    def insert_commit_to_db(self, db_conn, commit: Commit):
        """
        Writes commit into db. Duplicated commit would be ignore and not written to DB.
        """
        try:
            commit.generate_uniqueness_hash()
            add_commit_row(
                db_conn, commit.token_id, commit.encrypted_commit_hash, commit.repo_slug,
                commit.encrypted_branch_name, commit.encrypted_filename, commit.encrypted_linenumber,
                commit.author_name, commit.author_email, commit.pusher_username, commit.pusher_email,
                commit.committer_name, commit.committer_email, commit.encrypted_location_url,
                commit.repo_public, commit.uniqueness_hash,
            )
        except psycopg2.errors.UniqueViolation:
            self.logger.info(f'commit {commit.commit_hash} already exists.', exc_info=1)

    def write_to_db(self, encrypted_secrets, commit):
        """
        Writes secret metadata to the gd_corpus_db,
        and  writes the raw secret and other factors to vault.

        Accepts: encrypted_secrets, a list of Secret objects with encrypted_secret property set
            commit, commit hash scanned
            repo, repo committed to
            branch, branch of repo where commit was pushed
            username, GitHub short handle of user (pusher)
            email, email address of user (pusher)
        Returns: list of token_ids written to database (or empty list)
        """

        if len(encrypted_secrets) < 1:
            self.logger.info('Nothing to write to db.')
            return []

        try:
            db_conn = connect_db()
        except Exception as e:
            self.logger.error('Failed to connect to db: %s' % e, exc_info=1)
            return []

        token_ids = []
        for secret in encrypted_secrets:
            if secret.encrypted_secret and secret.filename and secret.linenumber:
                try:
                    token_id = self.insert_token_to_db(db_conn, secret)
                    secret.id = token_id
                    commit.token_id = token_id
                    commit.filename = secret.filename
                    commit.linenumber = secret.linenumber
                    self.write_to_vault(secret)
                    self.insert_commit_to_db(db_conn, commit)
                    self.logger.info(
                        'Successfully wrote token #%s to database from commit: %s.' % (
                            token_id, commit.commit_hash,
                        ),
                    )
                    token_ids.append(token_id)
                except Exception as e:
                    self.logger.error(
                        'Failed to write token from commit %s: %s' % (commit.commit_hash, e), exc_info=1,
                    )
            else:
                self.logger.error(
                    'No encrypted secret, filename, and linenumber to write to database.',
                )
        return token_ids

    def on_delivery(self, err, msg):
        if err:
            self.logger.error(
                'Delivery report: Failed sending message {0}'.format(
                    msg.value(),
                ), extra={'error': err},
            )
            # We could retry sending the message
        else:
            self.logger.info(
                'Message produced, offset: {0}'.format(msg.offset()),
            )

    def write_messages_to_queue(self, token_ids: list):
        # Disable writing message to notification queue since we are not consuming
        pass
        # for token_id in token_ids:
        #     message = json.dumps({'token_id': token_id})
        #     self.write_message_to_queue(message, self.notification_topic)

    def write_message_to_queue(self, message, topic_name):
        """
        Writes message to Kafka topic.
        """
        try:
            if self.tracer:
                self.tracer.inject(
                    self.tracer.active_span,
                    Format.TEXT_MAP, message,
                )
            self.producer.produce(
                topic_name, message,
                'key', -1, on_delivery=self.on_delivery,
            )
            self.producer.poll(0)
        except Exception as e:
            self.logger.error(
                'Failed to write to %s topic of Kafka queue: %s' % (
                    topic_name, e,
                ), exc_info=1,
            )
        finally:
            self.producer.flush()

    def lookup_token_owners(self, secret_list):
        for secret in secret_list:
            secret.lookup_token_owner()

        return secret_list

    def get_commits_from_payload(self, json_payload):
        old_commit = json_payload['oldCommit']
        new_commit = json_payload['newCommit']
        repo_slug = json_payload['repoSlug']
        repo_public = json_payload['repoPublic']
        commits = []
        try:
            commits = self.commit_parser.get_intermediate_commits(
                repo_slug, old_commit, new_commit, repo_public,
            )
        except InstallationIDRequestException:
            self.logger.error(
                (
                    f'Failed to process commits from private repo {repo_slug}. '
                    'App is likely not installed.'
                ),
                exc_info=1,
            )
        return commits

    def process_message(self, json_payload):
        # get repo name, user id, commit hash, branch name from kafka message
        commit_hash = json_payload['commitHash']
        repo_slug = json_payload['repoSlug']
        branch_name = json_payload['branchName']
        pusher_username = json_payload['githubUser']
        repo_public = json_payload['repoPublic']

        commit = Commit(commit_hash, repo_slug, branch_name)
        commit.pusher_username = pusher_username
        commit.repo_public = repo_public

        span_ctx = self.tracer.extract(Format.TEXT_MAP, json_payload)
        span_tags = {'commitHash': commit}

        # get diff of commit
        with self.tracer.start_active_span(
            'scan worker - create diff',
            child_of=span_ctx, tags=span_tags,
        ):
            try:
                github = self.get_github_client_for_repo(commit.repo_slug, commit.repo_public)
                self.create_diff_file(
                    commit.repo_slug,
                    commit.commit_hash,
                    github,
                )
            except InstallationIDRequestException:
                self.logger.error(
                    (
                        f'Failed to retrieve installation ID for repo {commit.repo_slug}. '
                        'App is likely not installed on private repo.'
                    ),
                    exc_info=1,
                )
                return

        # run detect-secrets
        with self.tracer.start_active_span(
            'scan worker - detect secrets scan',
            child_of=span_ctx, tags=span_tags,
        ):
            detect_secrets_output = self.run_detect_secrets(commit.commit_hash)
            # WDSExperiments(self.logger).compare_detectors(
            #     self.diff_filename, 'GitHub Credentials',
            #     'GitHub Credentials V2', commit.repo_slug,
            #     commit.commit_hash,
            # )

        # attempt validation of potential secrets
        with self.tracer.start_active_span(
            'scan worker - validate secrets',
            child_of=span_ctx, tags=span_tags,
        ):
            validated_secrets = self.validate_secrets(
                detect_secrets_output, commit.commit_hash,
            )

        # extract filename and linenumber of validated secrets
        with self.tracer.start_active_span(
            'scan worker - extract filename & linenumber',
            child_of=span_ctx, tags=span_tags,
        ):
            validated_secrets_with_metadata = self.extract_filename_linenumber(
                validated_secrets,
            )

        encrypted_secrets = validated_secrets_with_metadata

        # lookup pusher email, committer/author name and email
        with self.tracer.start_active_span(
            'scan worker - lookup email',
            child_of=span_ctx, tags=span_tags,
        ):
            if len(encrypted_secrets) > 0:
                commit.pusher_email, commit.author_name, commit.author_email, \
                    commit.committer_name, commit.committer_email = \
                    self.lookup_additional_github_info(
                        commit.pusher_username,
                        commit.repo_slug,
                        commit.commit_hash,
                        commit.repo_public,
                    )

        # lookup token owner
        with self.tracer.start_active_span(
            'scan worker - lookup token_owner',
            child_of=span_ctx, tags=span_tags,
        ):
            encrypted_secrets = self.lookup_token_owners(encrypted_secrets)

        # write encrypted secrets to db
        with self.tracer.start_active_span(
            'scan worker - write to database',
            child_of=span_ctx, tags=span_tags,
        ):
            token_ids = self.write_to_db(encrypted_secrets, commit)

        # write each token_id written to db to notification queue
        with self.tracer.start_active_span(
            'scan worker - write to notification queue',
            child_of=span_ctx, tags=span_tags,
        ):
            self.write_messages_to_queue(token_ids)

    def process_message_safe(self, json_payload):
        try:
            self.process_message(json_payload)
        except Exception:
            self.logger.error(
                f'Failed to process message {json_payload}',
                exc_info=1,
            )

    @asyncio.coroutine
    def run(self):
        self.logger.info('The diff scan worker has started')
        self.consumer.subscribe([self.diff_scan_topic])
        while self.running:
            msg = self.consumer.poll(1)
            if msg is not None and msg.error() is None:
                key = None
                if msg.key():
                    key = msg.key().decode('utf-8')
                self.logger.info(
                    'Message consumed: topic={0}, partition={1}, offset={2}, key={3}, value={4}'.format(
                        msg.topic(),
                        msg.partition(),
                        msg.offset(),
                        key,
                        msg.value().decode('utf-8'),
                    ),
                )

                json_message = msg.value().decode('utf-8')
                json_payload = json.loads(json_message)
                if 'commitHash' in json_payload:
                    # commit already extracted
                    self.process_message_safe(json_payload)
                elif 'oldCommit' in json_payload and 'newCommit' in json_payload:
                    commits = self.get_commits_from_payload(json_payload)
                    for commit_hash in commits:
                        json_payload['commitHash'] = commit_hash
                        self.process_message_safe(json_payload)

            else:
                yield from asyncio.sleep(self.async_sleep_time)
        self.consumer.unsubscribe()
        self.consumer.close()
