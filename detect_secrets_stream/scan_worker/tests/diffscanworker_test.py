import asyncio
import json
import os
from unittest import mock
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

import psycopg2
import pytest
import responses
from requests.exceptions import HTTPError

from .messagemock_test import MessageMock
from detect_secrets_stream.github_client.github_app import GitHubApp
from detect_secrets_stream.github_client.installation_id_request_exception import InstallationIDRequestException
from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.scan_worker.diffscanworker import DiffScanWorker
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.secret_corpus_db.data_cleanliness_exception import DataCleanlinessException
from detect_secrets_stream.util.conf import ConfUtil


class DiffScanWorkerTest (TestCase):

    def setUp(self):
        self.github_host = ConfUtil.load_github_conf()['host']
        self.email_domain = 'test.test'
        self.kafka_config = {
            'client.id': 'scan-worker-test',
            'group.id': 'scan-worker-test-group',
            'bootstrap.servers': 'fake_KAFKA_BROKERS_SASL',
            'security.protocol': 'SASL_SSL',
            'sasl.mechanisms': 'PLAIN',
            'sasl.username': 'token',
            'sasl.password': 'fake_KAFKA_API_KEY',
            'api.version.request': True,
            'broker.version.fallback': '0.10.2.1',
            'log.connection.close': False,
        }
        self.test_diff_topic = 'diff-scan-test'
        self.test_notification_topic = 'notification-test'
        self.diffscanworker = DiffScanWorker(
            self.kafka_config, self.test_diff_topic, self.test_notification_topic, async_sleep_time=0.1,
        )
        self.diff_filename = './diff.txt'
        self.test_commit = '0000000000'
        self.test_repo = 'test-repo'
        self.test_branch = 'test-branch'
        self.test_user = 'test-user'
        self.test_json_payload = {
            'commitHash': self.test_commit,
            'repoSlug': self.test_repo,
            'branchName': self.test_branch,
            'githubUser': self.test_user,
            'repoPublic': 'true',
        }
        self.test_json_payload_private = {
            'commitHash': self.test_commit,
            'repoSlug': self.test_repo,
            'branchName': self.test_branch,
            'githubUser': self.test_user,
            'repoPublic': 'false',
        }
        self.test_json_payload_commit_range = {
            'oldCommit': self.test_commit,
            'newCommit': self.test_commit,
            'repoSlug': self.test_repo,
            'branchName': self.test_branch,
            'githubUser': self.test_user,
            'repoPublic': 'true',
        }

    def tearDown(self):
        if os.path.exists(self.diff_filename):
            os.remove(self.diff_filename)
        self.diffscanworker.stop()

    @patch('detect_secrets_stream.github_client.github_app.GitHubApp._create_installation_token')
    @patch('detect_secrets_stream.github_client.github_app.GitHubApp._get_installation_id')
    @responses.activate
    def test_create_diff_file_for_private_repo(
        self, mock_get_install_id, mock_create_install_token,
    ):
        repo = 'fake-org/fake-repo'
        commit = '0000000000'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/commits/{commit}',
            headers={'X-RateLimit-Remaining': 'test'}, body='this is a test diff', status=200,
        )
        mock_get_install_id.return_value = 1
        self.diffscanworker.create_diff_file(
            repo, commit, github=GitHubApp().get_github_client(repo),
        )
        with open(self.diff_filename, 'r') as diff_file:
            content = diff_file.read()
        self.assertEqual(content, 'this is a test diff')
        mock_get_install_id.assert_called_with('fake-org/fake-repo')
        mock_create_install_token.assert_called_with(1)

    @responses.activate
    def test_create_diff_file(self):
        repo = 'fake-org/fake-repo'
        commit = '0000000000'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/commits/{commit}',
            headers={'X-RateLimit-Remaining': 'test'}, body='this is a test diff', status=200,
        )
        self.diffscanworker.create_diff_file(repo, commit, self.diffscanworker.github)
        with open(self.diff_filename, 'r') as diff_file:
            content = diff_file.read()
        self.assertEqual(content, 'this is a test diff')

    @responses.activate
    @patch('logging.Logger.error')
    def test_create_diff_file_bad_request(self, mock):
        repo = 'fake-org/fake-repo'
        commit = '0000000000'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/commits/{commit}',
            headers={'X-RateLimit-Remaining': 'test'}, body='not found', status=401,
        )
        with pytest.raises(HTTPError, match=r'401 .*'):
            self.diffscanworker.create_diff_file(repo, commit, self.diffscanworker.github)
        mock.assert_called()

    def test_run_detect_secrets_no_results(self):
        commit = '0000000000'
        diff_file_content = 'no secrets here!'
        with open(self.diff_filename, 'w') as diff_file:
            diff_file.write(diff_file_content)
        ds_output = json.loads(self.diffscanworker.run_detect_secrets(commit))
        self.assertNotIn(self.diff_filename, ds_output['results'])
        self.assertEqual(0, len(ds_output['results']))

    def test_run_detect_secrets_slack(self):
        commit = '0000000000'
        fake_slack_token = 'xoxp-1-testytesttest'  # pragma: whitelist secret
        with open(self.diff_filename, 'w') as diff_file:
            diff_file.write(fake_slack_token)
        ds_output = json.loads(self.diffscanworker.run_detect_secrets(commit, verify=False))
        self.assertIn(self.diff_filename, ds_output['results'])
        self.assertIn(
            fake_slack_token, [
                secret['secret'] for secret in ds_output['results'][self.diff_filename]
            ],
        )
        self.assertIn(
            'Slack Token', [
                secret['type'] for secret in ds_output['results'][self.diff_filename]
            ],
        )
        self.assertIn(
            1, [
                secret['line_number']
                for secret in ds_output['results'][self.diff_filename]
            ],
        )

    def test_validate_secrets_slack(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'Slack Token',
                        'is_verified': True,
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertIn(
            'fake_secret', [
                secret.secret for secret in validated_secrets
            ],
        )
        self.assertIn(
            'Slack Token', [
                secret.secret_type for secret in validated_secrets
            ],
        )
        self.assertIn(
            1, [secret.diff_file_linenumber for secret in validated_secrets],
        )

    def test_validate_secrets_slack_unverified(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'Slack Token',
                        'is_verified': False,
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertEqual(0, len(validated_secrets))

    def test_validate_secrets_slack_no_validation_info(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'Slack Token',
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertEqual(0, len(validated_secrets))

    def test_validate_secrets_unsupported_type(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'fake_type',
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertEqual(0, len(validated_secrets))

    def test_validate_secrets_no_verified_results(self):
        commit = '0000000000'
        ds_output = {
            'results': {},
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertEqual(0, len(validated_secrets))

    def test_validate_secrets_multifactor_verified(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'multifactor',
                        'is_verified': True, 'other_factors': {'second factor': 'test'},
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertIn(
            'fake_secret', [
                secret.secret for secret in validated_secrets
            ],
        )
        self.assertIn(
            'multifactor', [
                secret.secret_type for secret in validated_secrets
            ],
        )
        self.assertIn(
            1, [secret.diff_file_linenumber for secret in validated_secrets],
        )
        self.assertIn(
            {'second factor': 'test'}, [secret.other_factors for secret in validated_secrets],
        )

    def test_validate_secrets_multifactor_unverified(self):
        commit = '0000000000'
        ds_output = {
            'results': {
                self.diff_filename: [
                    {
                        'line_number': 1, 'secret': 'fake_secret',
                        'hashed_secret': 'fake_hashed_secret', 'type': 'multifactor',
                        'is_verified': False, 'other_factors': {'second factor': 'test'},
                    },
                ],
            },
        }
        validated_secrets = self.diffscanworker.validate_secrets(
            json.dumps(ds_output), commit,
        )
        self.assertEqual(0, len(validated_secrets))

    def test_extract_filename_linenumber(self):
        test_secret_1 = Secret('test_secret_1', 'test_type')
        test_secret_2 = Secret('test_secret_2', 'test_type')
        test_secret_3 = Secret('test_secret_3', 'test_type')
        test_secret_4 = Secret('test_secret_4', 'test_type')

        with open(self.diff_filename, 'w') as diff_file:
            with open('detect_secrets_stream/scan_worker/test_data/diff_files/generic.diff') as test_diff:
                test_diff_data = test_diff.read()
                diff_file.write(test_diff_data)

        # secret is in metadata
        test_secret_1.diff_file_linenumber = 3
        # secret line was neither added or removed
        test_secret_2.diff_file_linenumber = 16
        # secret line was removed
        test_secret_3.diff_file_linenumber = 17
        # secret line was added
        test_secret_4.diff_file_linenumber = 18

        test_secrets = [
            test_secret_1, test_secret_2,
            test_secret_3, test_secret_4,
        ]
        self.diffscanworker.extract_filename_linenumber(test_secrets)

        self.assertEqual(test_secret_1.filename, '')
        self.assertEqual(test_secret_1.linenumber, -1)

        self.assertEqual(test_secret_2.filename, 'diffscanworker.py')
        self.assertEqual(test_secret_2.linenumber, 42)

        self.assertEqual(test_secret_3.filename, 'diffscanworker.py')
        self.assertEqual(test_secret_3.linenumber, 42)

        self.assertEqual(test_secret_4.filename, 'diffscanworker.py')
        self.assertEqual(test_secret_4.linenumber, 43)

    @patch('detect_secrets_stream.scan_worker.diffscanworker.GHElookup')
    def test_lookup_additional_github_info(self, mock_ghe_lookup):
        user = 'username'
        repo = 'some-org/some-repo'
        commit = '000000'
        repo_public = 'true'
        self.diffscanworker = DiffScanWorker(
            self.kafka_config, self.test_diff_topic, self.test_notification_topic, async_sleep_time=0.1,
        )
        mock_ghe_lookup.return_value.ghe_email_lookup.return_value = 'pusheremail'
        mock_ghe_lookup.return_value.ghe_author_committer_lookup.return_value = \
            'author', 'authoremail', 'committer', 'committeremail'

        result = self.diffscanworker.lookup_additional_github_info(user, repo, commit, repo_public)

        assert result == ('pusheremail', 'author', 'authoremail', 'committer', 'committeremail')
        mock_ghe_lookup.assert_called_with(self.diffscanworker.github)
        mock_ghe_lookup.return_value.ghe_email_lookup.assert_called_with(user)
        mock_ghe_lookup.return_value.ghe_author_committer_lookup.assert_called_with(repo, commit)

    @patch('detect_secrets_stream.scan_worker.diffscanworker.GitHubApp.get_github_client')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.GHElookup')
    def test_lookup_additional_github_info_private_repo(self, mock_ghe_lookup, mock_get_private_client):
        user = 'username'
        repo = 'some-org/some-repo'
        commit = '000000'
        repo_public = 'false'
        mock_ghe_lookup.return_value.ghe_email_lookup.return_value = 'pusheremail'
        mock_ghe_lookup.return_value.ghe_author_committer_lookup.return_value = \
            'author', 'authoremail', 'committer', 'committeremail'

        result = self.diffscanworker.lookup_additional_github_info(user, repo, commit, repo_public)

        assert result == ('pusheremail', 'author', 'authoremail', 'committer', 'committeremail')
        mock_ghe_lookup.assert_called_with(mock_get_private_client.return_value)
        mock_ghe_lookup.return_value.ghe_email_lookup.assert_called_with(user)
        mock_ghe_lookup.return_value.ghe_author_committer_lookup.assert_called_with(repo, commit)

    def test_get_github_client_for_repo_public(self):
        repo = 'some-org/some-repo'
        repo_public = 'true'
        client = self.diffscanworker.get_github_client_for_repo(repo, repo_public)
        assert client == self.diffscanworker.github

    @patch('detect_secrets_stream.scan_worker.diffscanworker.GitHubApp.get_github_client')
    def test_get_github_client_for_repo_private(self, mock_get_private_client):
        repo = 'some-org/some-repo'
        repo_public = 'false'
        client = self.diffscanworker.get_github_client_for_repo(repo, repo_public)
        assert client == mock_get_private_client.return_value

    @patch('detect_secrets_stream.scan_worker.diffscanworker.Vault')
    def test_write_to_vault(self, mock_vault):
        mock_vault.return_value.create_or_update_secret = mock_create_or_update = MagicMock()
        mock_create_or_update.return_value = MagicMock()

        test_secret = Secret('test_secret', 'test_type')
        test_secret.id = 1
        test_secret.other_factors = {'another': 'factor'}

        self.diffscanworker.write_to_vault(test_secret)

        mock_create_or_update.assert_called_with(1, 'test_secret', {'another': 'factor'})

    @patch('detect_secrets_stream.scan_worker.diffscanworker.Vault')
    def test_write_to_vault_fails(self, mock_vault):
        mock_vault.return_value.create_or_update_secret = mock_create_or_update = MagicMock()
        mock_create_or_update.return_value.raise_for_status.side_effect = HTTPError('oops')

        test_secret = Secret('test_secret', 'test_type')
        test_secret.other_factors = {'another': 'factor'}
        test_secret.id = 1

        with pytest.raises(HTTPError):
            self.diffscanworker.write_to_vault(test_secret)

    @patch('detect_secrets_stream.scan_worker.diffscanworker.Vault')
    def test_write_to_vault_fails_data_cleanliness(self, mock_vault):
        mock_vault.return_value.create_or_update_secret = mock_create_or_update = MagicMock()
        mock_create_or_update.return_value.raise_for_status.side_effect = HTTPError('oops')

        test_secret = Secret('test_secret', 'test_type')
        test_secret.other_factors = {'another': 'factor'}
        test_secret.encrypted_other_factors = None
        test_secret.id = None

        with pytest.raises(DataCleanlinessException):
            self.diffscanworker.write_to_vault(test_secret)

    @patch('detect_secrets_stream.scan_worker.diffscanworker.get_token_id_by_type_hash')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_token_row')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.connect_db')
    def test_insert_token_to_db_no_duplicate(self, mock_conn, mock_add_token, mock_get_token_id):
        test_secret = Secret('test_secret', 'test_type')
        test_secret.live = True
        test_secret.filename = 'filename.test'
        test_secret.linenumber = 100
        test_secret.other_factors = {'another': 'factor'}
        test_token_id = 'token_id'

        mock_get_token_id.return_value = []
        mock_add_token.return_value = test_token_id

        token_id = self.diffscanworker.insert_token_to_db(
            mock_conn, test_secret,
        )

        assert token_id == test_token_id
        mock_get_token_id.assert_called_with(
            mock.ANY, test_secret.secret_type, test_secret.hashed_secret,
        )
        mock_add_token.assert_called_with(
            mock.ANY, None, test_secret.secret_type,
            mock.ANY, None, test_secret.uuid, True, test_secret.hashed_secret,
            test_secret.owner_email,
        )

    @patch('detect_secrets_stream.scan_worker.diffscanworker.get_token_id_by_type_hash')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_token_row')
    def test_insert_token_to_db_has_duplicate(self, mock_add_token, mock_get_token_id):
        test_secret = Secret('test_secret', 'test_type')
        test_token_id = 'token_id'
        mock_get_token_id.return_value = [test_token_id]

        token_id = self.diffscanworker.insert_token_to_db(
            'mock_conn', test_secret,
        )

        assert token_id == test_token_id
        mock_get_token_id.assert_called_with(
            mock.ANY, test_secret.secret_type, test_secret.hashed_secret,
        )
        mock_add_token.assert_not_called()

    @patch('detect_secrets_stream.scan_worker.diffscanworker.get_token_id_by_type_hash')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_token_row')
    def test_insert_token_to_db_has_duplicate_tuple(self, mock_add_token, mock_get_token_id):
        test_secret = Secret('test_secret', 'test_type')
        test_token_id = 'token_id'
        mock_get_token_id.return_value = [(test_token_id,)]

        token_id = self.diffscanworker.insert_token_to_db(
            'mock_conn', test_secret,
        )

        assert token_id == test_token_id
        mock_get_token_id.assert_called_with(
            mock.ANY, test_secret.secret_type, test_secret.hashed_secret,
        )
        mock_add_token.assert_not_called()

    @patch('detect_secrets_stream.scan_worker.diffscanworker.get_token_id_by_type_hash')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_token_row')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.connect_db')
    def test_insert_token_with_uuid(self, mock_conn, mock_add_token, mock_get_token_id):
        test_secret = Secret('test_secret', 'test_type')
        test_secret.live = True
        test_uuid = 'test_uuid'
        test_secret.uuid = test_uuid
        test_token_id = 'token_id'

        mock_get_token_id.return_value = []
        mock_add_token.return_value = test_token_id

        token_id = self.diffscanworker.insert_token_to_db(
            mock_conn, test_secret,
        )

        assert token_id == test_token_id
        mock_get_token_id.assert_called_with(
            mock.ANY, test_secret.secret_type, test_secret.hashed_secret,
        )
        mock_add_token.assert_called_with(
            mock.ANY, None,
            'test_type', mock.ANY,
            None, 'test_uuid', True,
            mock.ANY, mock.ANY,
        )

    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_commit_row')
    def test_insert_commit_to_db_has_duplicate(self, mock_add_commit):
        test_commit = Commit(commit_hash='0000000000', repo_slug='test-repo', branch_name='test-branch')
        test_commit.author_name = 'test-author'
        test_commit.author_email = f'test-author@{self.email_domain}'
        test_commit.pusher_username = 'test-pusher'
        test_commit.pusher_email = f'test-pusher@{self.email_domain}'
        test_commit.committer_name = 'test-committer'
        test_commit.committer_email = f'test-committer@{self.email_domain}'
        test_commit.token_id = 123

        mock_add_commit.side_effect = psycopg2.errors.UniqueViolation('foo')

        self.diffscanworker.insert_commit_to_db(
            'mock_conn', test_commit,
        )

        assert test_commit.uniqueness_hash is not None
        mock_add_commit.assert_called_with(
            mock.ANY, test_commit.token_id, test_commit.encrypted_commit_hash, test_commit.repo_slug,
            test_commit.encrypted_branch_name, test_commit.encrypted_filename, test_commit.encrypted_linenumber,
            test_commit.author_name, test_commit.author_email, test_commit.pusher_username,
            test_commit.pusher_email, test_commit.committer_name, test_commit.committer_email,
            test_commit.encrypted_location_url, test_commit.repo_public, test_commit.uniqueness_hash,
        )

    @patch('detect_secrets_stream.scan_worker.diffscanworker.add_commit_row')
    @patch('detect_secrets_stream.scan_worker.diffscanworker.connect_db')
    def test_write_to_db(self, mock_connect, mock_add_commit):
        test_commit = Commit(commit_hash='0000000000', repo_slug='test-repo', branch_name='test-branch')
        test_commit.location_url = 'https://abc.com'
        test_commit.author_name = 'test-author'
        test_commit.author_email = f'test-author@{self.email_domain}'
        test_commit.pusher_username = 'test-pusher'
        test_commit.pusher_email = f'test-pusher@{self.email_domain}'
        test_commit.committer_name = 'test-committer'
        test_commit.committer_email = f'test-committer@{self.email_domain}'
        test_secret = Secret('test_secret', 'test_type')
        test_secret.filename = 'test_filename'
        test_secret.linenumber = 100
        test_secret.other_factors = {'second factor': 'another one'}
        encrypted_secrets = [test_secret]
        mock_connect.return_value = 'test_connection'
        self.diffscanworker.insert_token_to_db = mock_insert_token = MagicMock()
        mock_insert_token.return_value = 1
        self.diffscanworker.write_to_vault = MagicMock()

        token_ids = self.diffscanworker.write_to_db(encrypted_secrets, test_commit)
        mock_connect.assert_called()
        mock_insert_token.assert_called_with('test_connection', test_secret)
        mock_add_commit.assert_called_with(
            'test_connection', 1, test_commit.encrypted_commit_hash, test_commit.repo_slug,
            test_commit.encrypted_branch_name, test_commit.encrypted_filename, test_commit.encrypted_linenumber,
            test_commit.author_name, test_commit.author_email, test_commit.pusher_username,
            test_commit.pusher_email, test_commit.committer_name, test_commit.committer_email,
            test_commit.encrypted_location_url, test_commit.repo_public, test_commit.uniqueness_hash,
        )
        self.assertEqual(token_ids, [1])
        self.diffscanworker.write_to_vault.assert_called()

    def test_write_messages_to_queue(self):
        for count in range(3):
            self.diffscanworker.write_message_to_queue = MagicMock()

            ids = []
            for i in range(count):
                ids.append('mock_id')

            self.diffscanworker.write_messages_to_queue(ids)
            self.diffscanworker.write_message_to_queue.call_count = count

    @patch('logging.Logger.error')
    def test_write_message_to_queue(self, mock_error):
        test_topic = 'notification-test'
        test_message = '{testy: test}'
        self.diffscanworker.producer = MagicMock()

        self.diffscanworker.write_message_to_queue(test_message, test_topic)

        self.diffscanworker.producer.produce.assert_called()
        self.diffscanworker.producer.poll.assert_called()
        self.diffscanworker.producer.flush.assert_called()
        mock_error.assert_not_called()

    @patch('detect_secrets_stream.scan_worker.commitparser.CommitParser.get_intermediate_commits')
    def test_get_commits_from_payload(self, mock_inter_commits):
        intermediate_commits = ['commit_1', 'commit_2']
        mock_inter_commits.return_value = intermediate_commits

        commits = self.diffscanworker.get_commits_from_payload(self.test_json_payload_commit_range)

        assert mock_inter_commits.called is True
        assert commits == ['commit_1', 'commit_2']

    @pytest.mark.asyncio
    def test_run_no_messages(self):
        consumer_wrapper = MagicMock()
        consumer_wrapper.poll.side_effect = [None]
        self.diffscanworker.consumer = consumer_wrapper

        consumer_wrapper.subscribe.assert_not_called()
        consumer_wrapper.poll.assert_not_called()
        consumer_wrapper.unsubscribe.assert_not_called()
        consumer_wrapper.close.assert_not_called()

        loop = asyncio.get_event_loop()
        loop.call_later(0.1, self.diffscanworker.stop)
        loop.run_until_complete(self.diffscanworker.run())

        consumer_wrapper.subscribe.assert_called()
        consumer_wrapper.poll.assert_called()
        consumer_wrapper.unsubscribe.assert_called()
        consumer_wrapper.close.assert_called()

    @pytest.mark.asyncio
    def test_run_with_message(self):
        self.diffscanworker.tracer = MagicMock()
        queue_message_value = json.dumps(self.test_json_payload)
        message = MessageMock(
            self.test_diff_topic, -1,
            0, 'key', queue_message_value,
        )
        consumer_wrapper = MagicMock()
        # return twice, first time is message, second time is None
        # Then we will break out of the running loop
        consumer_wrapper.poll.side_effect = [message, None]

        self.diffscanworker.consumer = consumer_wrapper
        self.diffscanworker.process_message = MagicMock()

        loop = asyncio.get_event_loop()
        loop.call_later(0.1, self.diffscanworker.stop)
        loop.run_until_complete(self.diffscanworker.run())

        self.diffscanworker.consumer.subscribe.assert_called()
        self.diffscanworker.consumer.poll.assert_called()
        self.diffscanworker.consumer.unsubscribe.assert_called()
        self.diffscanworker.consumer.close.assert_called()
        self.diffscanworker.process_message.assert_called_with(
            self.test_json_payload,
        )

    def test_process_message(self):
        self.diffscanworker.tracer = MagicMock()
        self.diffscanworker.create_diff_file = MagicMock()
        self.diffscanworker.run_detect_secrets = MagicMock()
        self.diffscanworker.validate_secrets = MagicMock()
        self.diffscanworker.extract_filename_linenumber = MagicMock()
        self.diffscanworker.lookup_additional_github_info = MagicMock()
        self.diffscanworker.write_to_db = MagicMock()
        self.diffscanworker.write_messages_to_queue = MagicMock()

        self.diffscanworker.process_message(self.test_json_payload)

        self.diffscanworker.create_diff_file.assert_called()
        self.diffscanworker.run_detect_secrets.assert_called()
        self.diffscanworker.validate_secrets.assert_called()
        self.diffscanworker.extract_filename_linenumber.assert_called()
        self.diffscanworker.lookup_additional_github_info.assert_not_called()
        self.diffscanworker.write_to_db.assert_called()
        self.diffscanworker.write_messages_to_queue.assert_called()

    def test_process_message_private_repo(self):
        self.diffscanworker.tracer = MagicMock()
        self.diffscanworker.create_diff_file = MagicMock()
        self.diffscanworker.run_detect_secrets = MagicMock()
        self.diffscanworker.validate_secrets = MagicMock()
        self.diffscanworker.extract_filename_linenumber = MagicMock()
        self.diffscanworker.lookup_additional_github_info = MagicMock()
        self.diffscanworker.write_to_db = MagicMock()
        self.diffscanworker.write_messages_to_queue = MagicMock()
        self.diffscanworker.github_app.get_github_client = MagicMock()

        self.diffscanworker.process_message(self.test_json_payload_private)

        self.diffscanworker.create_diff_file.assert_called()
        self.diffscanworker.run_detect_secrets.assert_called()
        self.diffscanworker.validate_secrets.assert_called()
        self.diffscanworker.extract_filename_linenumber.assert_called()
        self.diffscanworker.lookup_additional_github_info.assert_not_called()
        self.diffscanworker.write_to_db.assert_called()
        self.diffscanworker.write_messages_to_queue.assert_called()

    def test_process_message_private_repo_app_not_installed(self):
        self.diffscanworker.tracer = MagicMock()
        self.diffscanworker.create_diff_file = MagicMock()
        self.diffscanworker.run_detect_secrets = MagicMock()
        self.diffscanworker.validate_secrets = MagicMock()
        self.diffscanworker.extract_filename_linenumber = MagicMock()
        self.diffscanworker.lookup_additional_github_info = MagicMock()
        self.diffscanworker.write_to_db = MagicMock()
        self.diffscanworker.write_messages_to_queue = MagicMock()
        self.diffscanworker.github_app.get_github_client = \
            get_private_repo_github_mock = MagicMock()
        get_private_repo_github_mock.side_effect = InstallationIDRequestException()

        self.diffscanworker.process_message(self.test_json_payload_private)

        self.diffscanworker.create_diff_file.assert_not_called()
        self.diffscanworker.run_detect_secrets.assert_not_called()
        self.diffscanworker.validate_secrets.assert_not_called()
        self.diffscanworker.extract_filename_linenumber.assert_not_called()
        self.diffscanworker.lookup_additional_github_info.assert_not_called()
        self.diffscanworker.write_to_db.assert_not_called()
        self.diffscanworker.write_messages_to_queue.assert_not_called()

    def test_process_message_lookup_called(self):
        self.diffscanworker.tracer = MagicMock()
        self.diffscanworker.create_diff_file = MagicMock()
        self.diffscanworker.run_detect_secrets = MagicMock()
        self.diffscanworker.validate_secrets = MagicMock()
        self.diffscanworker.extract_filename_linenumber = mock_encrypt = MagicMock()
        self.diffscanworker.lookup_additional_github_info = mock_lookup = MagicMock()
        self.diffscanworker.write_to_db = MagicMock()
        self.diffscanworker.write_messages_to_queue = MagicMock()

        mock_encrypt.return_value = [Secret('test-secret', 'test-type')]
        mock_lookup.return_value = ('', '', '', '', '')
        self.diffscanworker.process_message(self.test_json_payload)

        self.diffscanworker.create_diff_file.assert_called()
        self.diffscanworker.run_detect_secrets.assert_called()
        self.diffscanworker.validate_secrets.assert_called()
        self.diffscanworker.extract_filename_linenumber.assert_called()
        self.diffscanworker.lookup_additional_github_info.assert_called()
        self.diffscanworker.write_to_db.assert_called()
        self.diffscanworker.write_messages_to_queue.assert_called()

    def test_process_message_safe(self):
        self.diffscanworker.process_message = MagicMock()
        self.diffscanworker.process_message_safe(self.test_json_payload)
        self.diffscanworker.process_message.assert_called_with(self.test_json_payload)

    @patch('logging.Logger.error')
    def test_process_message_safe_error(self, mock):
        self.diffscanworker.process_message = MagicMock()
        self.diffscanworker.process_message.side_effect = Exception
        self.diffscanworker.process_message_safe(self.test_json_payload)
        mock.assert_called()
