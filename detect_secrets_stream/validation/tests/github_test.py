import pytest
import responses
from detect_secrets.core.constants import VerifiedResult
from mock import patch

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.util.conf import ConfUtil
from detect_secrets_stream.validation.github import GHEValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestGHEValidator:

    email_domain = 'test.test'
    revocation_endpoint = ConfUtil.load_revoker_urls_conf()['github-revocation']
    owner_resolution_endpoint = ConfUtil.load_revoker_urls_conf()['github-owner-resolution']

    @pytest.mark.parametrize(
        'result, expected_valid',
        [
            (VerifiedResult.VERIFIED_TRUE, True),
            (VerifiedResult.VERIFIED_FALSE, False),
        ],
    )
    @patch('detect_secrets.plugins.github_enterprise.GheDetector.verify')
    def test_validate_ghe_token(self, mock_verify, result, expected_valid):
        mock_verify.return_value = result
        ghe_validator = GHEValidator()
        valid = ghe_validator.validate('test-token')
        assert valid is expected_valid

    @patch('detect_secrets.plugins.github_enterprise.GheDetector.verify')
    def test_validate_ghe_token_unverifiable(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        ghe_validator = GHEValidator()
        with pytest.raises(ValidationException):
            ghe_validator.validate('test-token')

    @responses.activate
    def test_ghe_resolve_owner(self):
        responses.add(
            responses.GET, self.owner_resolution_endpoint, status=200,
            body=f'{{"email": "test-email@{self.email_domain}"}}',
        )
        ghe_validator = GHEValidator()
        owner = ghe_validator.resolve_owner('test-token')
        assert owner == f'test-email@{self.email_domain}'

    @responses.activate
    def test_ghe_resolve_owner_login(self):
        responses.add(
            responses.GET, self.owner_resolution_endpoint, status=200,
            body='{"login": "test-login"}',
        )
        ghe_validator = GHEValidator()
        owner = ghe_validator.resolve_owner('test-token')
        assert owner == 'test-login'

    @responses.activate
    def test_ghe_resolve_owner_no_email_or_login(self):
        responses.add(
            responses.GET, self.owner_resolution_endpoint, status=200,
            body='{}',
        )
        ghe_validator = GHEValidator()
        owner = ghe_validator.resolve_owner('test-token')
        assert owner == ''

    @responses.activate
    def test_ghe_resolve_owner_not_found(self):
        responses.add(responses.GET, self.owner_resolution_endpoint, status=401)
        ghe_validator = GHEValidator()
        with pytest.raises(Exception):
            ghe_validator.resolve_owner('test-token')

    def test_hash_secret(self):
        test_text = 'something'
        expected_result = 'P8m2iUWdc4+MiKOkiqnjNUIBa3pAUuABqqU2/KdIE8s='
        result = GHEValidator.hash_token(test_text)
        assert result == expected_result

    @responses.activate
    def test_revoke_github_token(self):
        github_validator = GHEValidator()
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'jobs': {'Revoke Hashed GHE Token': {'triggered': True}}},
        )
        result = github_validator.revoke('test-secret')
        assert result is True

    @responses.activate
    def test_revoke_github_token_revoked_false(self):
        github_validator = GHEValidator()
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'jobs': {'Revoke Hashed GHE Token': {'triggered': False}}},
        )
        result = github_validator.revoke('test-secret')
        assert result is False

    @responses.activate
    def test_revoke_github_token_server_error(self):
        github_validator = GHEValidator()
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=500,
        )
        with pytest.raises(RevocationException, match=r'Failed to revoke GitHub token.'):
            github_validator.revoke('test-secret')

    @responses.activate
    def test_revoke_unexpected_payload(self):
        github_validator = GHEValidator()
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'not-the-expected-fields': True},
        )
        with pytest.raises(RevocationException, match=r'Failed to revoke GitHub token.'):
            github_validator.revoke('test-secret')
