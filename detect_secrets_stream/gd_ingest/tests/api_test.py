import base64
import json
from unittest import mock
from unittest.mock import patch

import pytest


class TestIngest:

    @pytest.fixture
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_kafka_conf')
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_basic_auth_conf')
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_github_conf')
    def ingest_app(self, mock_load_github_conf, mock_load_ba_conf, mock_load_kafka_conf):
        mock_kafka_config = {}
        mock_kafka_config['brokers_sasl'] = 'broker1.com, broker2.com, broker3.com'
        mock_kafka_config['api_key'] = 'someRandomTestKey'
        mock_load_kafka_conf.return_value = mock_kafka_config

        mock_basic_auth_config = {'ingest': 'testUser:testPassword'}
        mock_load_ba_conf.return_value = mock_basic_auth_config

        mock_github_config = {
            'tokens': 'someRandomTestToken',
            'host': 'github.company.com',
        }
        mock_load_github_conf.return_value = mock_github_config

        config = {
            'KAFKA_CLIENT_ID': 'gdIngest-Test',
        }
        config['USERNAME'], config['PASSWORD'] = mock_basic_auth_config['ingest'].split(':', 1)

        with mock.patch.dict('os.environ', values=config, clear=True):
            import detect_secrets_stream.gd_ingest.api as api
            app = api.app.test_client()
            return (api, app, config)

    @pytest.fixture
    def api_payload(self):
        return {
                'GITHUB_USER_LOGIN': 'testUser',
                'GIT_DIR': '/tmp',
                'GITHUB_USER_IP': '127.0.0.1',
                'GITHUB_REPO_NAME': 'git-defenders/push-hook-tester',
                'GITHUB_PULL_REQUEST_AUTHOR_LOGIN': 'testUser',
                'GITHUB_REPO_PUBLIC': 'true',
                'GITHUB_PUBLIC_KEY_FINGERPRINT': '44:e5:54:59:3e:06:76:4a:54:59:3ef5:68:fc:86:7f:1e:a2:8c',
                'GITHUB_PULL_REQUEST_HEAD': '',
                'GITHUB_PULL_REQUEST_BASE': '',
                'GITHUB_VIA': '',
                'GIT_PUSH_OPTION_COUNT': '',
                'GIT_PUSH_OPTION': [
                    '',
                ],
                'stdin': [
                    {
                        'old_value': 'ac3c0002019ef51ff759a9414421f93a29ef0705',
                        'new_value': '4f6a295992a42c41a78114155ac9033b2987abcf',
                        'ref_name': 'refs/heads/bernard_test',
                        'commits': 'ac3c0002019ef51ff759a9414421f93a29ef0705,4f6a295992a42c41a78114155ac9033b2987abcf',  # noqa E501
                        'total_commits': 2,
                        'max_commit_count': 20,
                    },
                ],
        }

    @pytest.fixture
    def api_payload_private(self):
        return {
                'GITHUB_USER_LOGIN': 'testUser',
                'GIT_DIR': '/tmp',
                'GITHUB_USER_IP': '127.0.0.1',
                'GITHUB_REPO_NAME': 'git-defenders/push-hook-tester',
                'GITHUB_PULL_REQUEST_AUTHOR_LOGIN': 'testUser',
                'GITHUB_REPO_PUBLIC': 'false',
                'GITHUB_PUBLIC_KEY_FINGERPRINT': '44:e5:54:59:3e:06:76:4a:54:59:3ef5:68:fc:86:7f:1e:a2:8c',
                'GITHUB_PULL_REQUEST_HEAD': '',
                'GITHUB_PULL_REQUEST_BASE': '',
                'GITHUB_VIA': '',
                'GIT_PUSH_OPTION_COUNT': '',
                'GIT_PUSH_OPTION': [
                    '',
                ],
                'stdin': [
                    {
                        'old_value': 'ac3c0002019ef51ff759a9414421f93a29ef0705',
                        'new_value': '4f6a295992a42c41a78114155ac9033b2987abcf',
                        'ref_name': 'refs/heads/justin_test',
                        'commits': 'ac3c0002019ef51ff759a9414421f93a29ef0705,4f6a295992a42c41a78114155ac9033b2987abcf',  # noqa E501
                        'total_commits': 2,
                        'max_commit_count': 20,
                    },
                ],
        }

    def _gen_basic_auth(self, username, password):
        return {
            'Authorization': 'Basic ' + base64.b64encode(
                bytes(
                    username + ':' + password, 'ascii',
                ),
            ).decode('ascii'),
        }

    @pytest.mark.parametrize(
        ('basic_auth_str', 'basic_auth'),
        [
            (None, {}),
            ('', {}),
            ('user:pass', {'user': 'pass'}),
            ('user1:pass1,user2:pass2', {'user1': 'pass1', 'user2': 'pass2'}),
            ('user1:pass1,wrong_string', {'user1': 'pass1'}),
        ],
    )
    def test_load_basic_auth(self, ingest_app, basic_auth_str, basic_auth):
        api = ingest_app[0]
        basic_auth_res = api.load_basic_auth(basic_auth_str)
        assert basic_auth_res == basic_auth

    def test_healthz(self, ingest_app):
        app = ingest_app[1]
        gd_ingest_health = app.get('/healthz')
        assert 200 == gd_ingest_health.status_code
        assert b'Service operational' == gd_ingest_health.data

    def test_delete_branch(self, ingest_app, api_payload):
        api, app, config = (ingest_app)
        api_payload['stdin'][0]['new_value'] = '0000000000000000000000000000000000000000'

        api.gd_ingest.add_message_to_queue = mock_add_msg = mock.MagicMock()
        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload),
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert mock_add_msg.called is False

    def test_payload_success(self, ingest_app, api_payload):
        api, app, config = (ingest_app)

        api.gd_ingest.add_message_to_queue = mock_add_msg = mock.MagicMock()
        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload),
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert mock_add_msg.call_count == 1
        mock_add_msg.assert_any_call(message=mock.ANY, topic_name='diff-scan')

    def test_payload_success_private(self, ingest_app, api_payload_private):
        api, app, config = (ingest_app)

        api.gd_ingest.add_message_to_queue = mock_add_msg = mock.MagicMock()
        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload_private),
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert mock_add_msg.call_count == 1
        mock_add_msg.assert_any_call(message=mock.ANY, topic_name='diff-scan')

    def test_skip_tags(self, ingest_app, api_payload):
        api, app, config = (ingest_app)

        api.gd_ingest.add_message_to_queue = mock_add_msg = mock.MagicMock()

        api_payload['stdin'][0]['ref_name'] = 'refs/tags/ignore'
        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload),
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        assert mock_add_msg.called is False

    def test_skip_non_public_or_private_repo(self, ingest_app, api_payload):
        api, app, config = (ingest_app)
        repo_visibility = ''

        api.gd_ingest.add_message_to_queue = mock_add_msg = mock.MagicMock()

        api_payload['GITHUB_REPO_PUBLIC'] = repo_visibility
        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload),
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        assert mock_add_msg.called is False

    def test_invalid_login(self, ingest_app, api_payload):
        api, app, config = (ingest_app)

        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=json.dumps(api_payload),
            headers=self._gen_basic_auth(config['USERNAME'], 'fake_password'),
            content_type='application/json',
        )
        assert 401 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert 'proper credentials' in resp_json['msg']

    @pytest.mark.parametrize(
        'invalid_payload',
        [
            'empty',
            json.dumps({}),
        ],
    )
    def test_invalid_payload(self, ingest_app, invalid_payload):
        api, app, config = (ingest_app)

        response = app.post(
            '/api/v1/webhook/pre-receive',
            data=invalid_payload,
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 500 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False

    @pytest.mark.parametrize(
        'missing_field',
        [
            'GITHUB_USER_LOGIN',
            'GITHUB_REPO_NAME',
            'GITHUB_REPO_PUBLIC',
            'stdin',
        ],
    )
    def test_validate_payload(self, missing_field, ingest_app, api_payload):
        api, app, config = (ingest_app)
        del api_payload[missing_field]
        assert api.is_payload_valid(api_payload) is False
