from unittest import TestCase

import pytest
from mock import MagicMock
from mock import patch

from ..vault import Vault
from ..vault_read_exception import VaultReadException


class VaultTest(TestCase):
    @patch("detect_secrets_stream.secret_corpus_db.vault.SecretsManagerV2")
    @patch("detect_secrets_stream.util.conf.ConfUtil.load_vault_conf")
    def setUp(self, mock_load_vault_conf, mock_hvac):
        import os

        # Mock the DEFAULT_SERVICE_NAME to return a string instead of MagicMock
        mock_hvac.DEFAULT_SERVICE_NAME = "secrets-manager"

        # Use environment variable or fallback to /tmp for compatibility
        vault_conf_path = os.environ.get("GD_VAULT_CONF", "/tmp/vault.prod.conf")
        sourceFile = open(vault_conf_path, "w")
        mock_vault_conf = "SECRETS_MANAGER_URL=https://instance.us-east.secrets-manager.appdomain.cloud\nSECRETS_MANAGER_AUTH_TYPE=iam\nSECRETS_MANAGER_APIKEY=key"
        print(mock_vault_conf, file=sourceFile)
        sourceFile.close()
        # mock_load_vault_conf.return_value = mock_vault_conf
        self.vault = Vault()
        self.mock_hvac = mock_hvac

    def test_create_or_update_secret_200(self):
        # Mock get_secret_by_name_type to return existing secret
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.get_result.return_value = {"id": "test-secret-id"}
        self.mock_hvac.return_value.get_secret_by_name_type.return_value = (
            mock_get_response
        )

        # Mock create_secret_version for update
        mock_update_response = MagicMock()
        mock_update_response.status_code = 200
        self.mock_hvac.return_value.create_secret_version.return_value = (
            mock_update_response
        )

        response = self.vault.create_or_update_secret(
            1, "super_secret", {"another": "factor"}
        )

        self.assertEqual(response.status_code, 200)

    def test_create_or_update_secret_404(self):
        # Mock get_secret_by_name_type to raise exception (secret doesn't exist)
        self.mock_hvac.return_value.get_secret_by_name_type.side_effect = Exception(
            "Not found"
        )

        # Mock create_secret for new secret
        mock_create_response = MagicMock()
        mock_create_response.status_code = 201
        self.mock_hvac.return_value.create_secret.return_value = mock_create_response

        response = self.vault.create_or_update_secret(
            1, "super_secret", {"another": "factor"}
        )

        self.assertEqual(response.status_code, 201)

    def test_read_secret(self):
        # Mock get_secret_by_name_type response
        mock_response = MagicMock()
        mock_response.get_result.return_value = {
            "data": {
                "secret": "super_secret",
                "other_factors": {"another": "one"},
            },
        }
        self.mock_hvac.return_value.get_secret_by_name_type.return_value = mock_response

        data = self.vault.read_secret(1)

        self.assertEqual(
            data, {"secret": "super_secret", "other_factors": {"another": "one"}}
        )

    def test_read_secret_fails(self):
        # Mock get_secret_by_name_type to raise exception
        self.mock_hvac.return_value.get_secret_by_name_type.side_effect = Exception(
            "oops"
        )

        with pytest.raises(VaultReadException):
            # token doesn't exist
            self.vault.read_secret(-1)
