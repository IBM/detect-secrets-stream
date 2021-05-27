import base64
from unittest import mock
from unittest.mock import patch

import pytest

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.util.conf import ConfUtil
from detect_secrets_stream.validation.validateException import ValidationException

github_host = ConfUtil.load_github_conf()['host']

ERROR_MESSAGE = (
    'Invalid API call. Check the documentation for correct API syntax: '
    'https://github.com/IBM/detect-secrets-stream'
    '/blob/master/detect_secrets_stream/gd_revoker/usage.md'
)


class TestRevocationApi:

    @pytest.fixture
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_basic_auth_conf')
    def revocation_app(self, mock_load_ba_conf):
        mock_basic_auth_config = {'revoker': 'testUser:testPassword', 'revoker-requires-auth': 'true'}
        mock_load_ba_conf.return_value = mock_basic_auth_config
        config = {}
        config['USERNAME'], config['PASSWORD'] = mock_basic_auth_config['revoker'].split(':', 1)

        with mock.patch.dict('os.environ', values=config, clear=True):
            import detect_secrets_stream.gd_revoker.api as api
            app = api.app.test_client()
            return (api, app, config)

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
    def test_load_basic_auth(self, revocation_app, basic_auth_str, basic_auth):
        api = revocation_app[0]
        basic_auth_res = api.load_basic_auth(basic_auth_str)
        assert basic_auth_res == basic_auth

    def test_healthz(self, revocation_app):
        api, app, config = (revocation_app)

        response = app.get(
            '/healthz',
        )
        assert 200 == response.status_code
        assert response.data == b'Service operational'

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_verify_success(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['is_live'] is True
        assert resp_json['message'] == 'Secret is active'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_verify_failure(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = False

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['is_live'] is False
        assert resp_json['message'] == 'Secret is remediated'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_verify_no_secret(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = None

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 404 == response.status_code
        resp_json = response.get_json()
        assert resp_json['is_live'] is None
        assert resp_json['message'] == 'Secret not found'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_verify_empty_secret(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_secret.delete_pi()
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['is_live'] is False
        assert resp_json['message'] == 'Secret was remediated, raw secret was cleaned up.'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_not_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_verify_exception(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.side_effect = ValidationException('error')

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['is_live'] is None
        assert resp_json['message'] == 'Failed to validate secret'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory(self, mock_db_biz, mock_verify, mock_revoke, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True
        mock_revoke.return_value = True

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert resp_json['message'] == 'Token with uuid some-uuid has been revoked'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory_revoked_false(self, mock_db_biz, mock_verify, mock_revoke, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True
        mock_revoke.return_value = False

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == 'Failed to revoke token with uuid some-uuid'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()
        mock_revoke.assert_called()

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory_empty_secret(self, mock_db_biz, mock_verify, mock_revoke, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_secret.delete_pi()
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True
        mock_revoke.return_value = False

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert resp_json['message'] == 'Token with uuid some-uuid is already inactive due to raw secret been cleaned up'  # noqa E501
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_not_called()
        mock_revoke.assert_not_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_unknown_type(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == \
            'Failed to revoke token with uuid some-uuid. Error: Can not revoke for unknown token type "test-type"'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_already_revoked(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'test-type')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = False

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert resp_json['message'] == 'Token with uuid some-uuid is already inactive'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()

    @patch('detect_secrets_stream.validation.github.GHEValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_ghe_token_verify_raises_exception(self, mock_db_biz, mock_verify, mock_revoke, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'GitHub Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.side_effect = Exception('oops')
        mock_revoke.return_value = True

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is True
        assert resp_json['message'] == 'Token with uuid some-uuid has been revoked'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()
        mock_revoke.assert_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_not_found(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = None

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 404 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == 'Token with uuid some-uuid was not found'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory_revoke_throws_exception(
        self, mock_db_biz, mock_verify, mock_revoke, revocation_app,
    ):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True
        mock_revoke.side_effect = RevocationException('oops')

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == 'Failed to revoke token with uuid some-uuid. Error: oops'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()
        mock_revoke.assert_called()

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory_verify_throws_exception(
        self, mock_db_biz, mock_verify, mock_revoke, revocation_app,
    ):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.side_effect = Exception('oops')
        mock_revoke.return_value = True

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        print(resp_json)
        assert resp_json['success'] is True
        assert resp_json['message'] == 'Token with uuid some-uuid has been revoked'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()
        mock_revoke.assert_called()

    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_get_secret_throws_exception(self, mock_db_biz, mock_verify, revocation_app):
        api, app, config = (revocation_app)
        mock_db_biz.return_value.get_secret_from_db_by_uuid.side_effect = Exception('oops')

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == 'Failed to revoke token with uuid some-uuid. Error: oops'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')

    @patch('detect_secrets_stream.validation.artifactory.ArtifactoryValidator.revoke')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.verify')
    @patch('detect_secrets_stream.gd_revoker.api.DbBiz')
    def test_revoke_token_artifactory_not_implemented(self, mock_db_biz, mock_verify, mock_revoke, revocation_app):
        api, app, config = (revocation_app)
        mock_secret = Secret('test-secret', 'Artifactory Credentials')
        mock_db_biz.return_value.get_secret_from_db_by_uuid.return_value = mock_secret
        mock_verify.return_value = True
        mock_revoke.return_value = None

        response = app.post(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 200 == response.status_code
        resp_json = response.get_json()
        assert resp_json['success'] is False
        assert resp_json['message'] == 'Revocation not implemented for token type Artifactory Credentials'
        mock_db_biz.return_value.get_secret_from_db_by_uuid.assert_called_with('some-uuid')
        mock_verify.assert_called()
        mock_revoke.assert_called()

    def test_404_page(self, revocation_app):
        api, app, config = (revocation_app)

        response = app.post(
            '/api/v1/token/some-uuid/incorrect-url',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 404 == response.status_code
        resp_json = response.get_json()
        assert resp_json['error'] == ERROR_MESSAGE

    def test_wrong_method_used(self, revocation_app):
        api, app, config = (revocation_app)

        response = app.get(
            '/api/v1/token/some-uuid/revoke',
            headers=self._gen_basic_auth(config['USERNAME'], config['PASSWORD']),
            content_type='application/json',
        )
        assert 405 == response.status_code
        resp_json = response.get_json()
        assert resp_json['error'] == ERROR_MESSAGE

    def test_401_unauthorized(self, revocation_app):
        api, app, config = (revocation_app)

        response = app.post(
            '/api/v1/token/some-uuid/verify',
            headers=self._gen_basic_auth('moo', 'cow'),
            content_type='application/json',
        )
        assert 401 == response.status_code
