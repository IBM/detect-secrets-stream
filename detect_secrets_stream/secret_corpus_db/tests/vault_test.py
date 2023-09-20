from unittest import TestCase

import pytest
from mock import MagicMock
from mock import patch

from ..vault import Vault
from ..vault_read_exception import VaultReadException


class VaultTest(TestCase):

    @patch('detect_secrets_stream.secret_corpus_db.vault.SecretsManagerV2')
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_vault_conf')
    def setUp(self, mock_load_vault_conf, mock_hvac):
        sourceFile = open('/home/travis/vault.prod.conf', 'w')
        mock_vault_conf = 'SECRETS_MANAGER_URL=https://instance.us-east.secrets-manager.appdomain.cloud\nSECRETS_MANAGER_AUTH_TYPE=iam\nSECRETS_MANAGER_APIKEY=key'
        print(mock_vault_conf, file = sourceFile)
        sourceFile.close()
        # mock_load_vault_conf.return_value = mock_vault_conf
        self.vault = Vault()
        self.mock_hvac = mock_hvac

    def test_create_or_update_secret_200(self):
        self.mock_hvac.return_value.secrets.kv.v1.create_or_update_secret.return_value = MagicMock(status_code=200)

        response = self.vault.create_or_update_secret(1, 'super_secret', {'another': 'factor'})

        self.assertEqual(response.status_code, 200)

    def test_create_or_update_secret_404(self):
        self.mock_hvac.return_value.secrets.kv.v1.create_or_update_secret.return_value = MagicMock(status_code=404)

        response = self.vault.create_or_update_secret(1, 'super_secret', {'another': 'factor'})

        self.assertEqual(response.status_code, 404)

    def test_read_secret(self):
        self.mock_hvac.return_value.secrets.kv.v1.read_secret.return_value = {
            'data': {
                'secret': 'super_secret',
                'other_factors': {'another': 'one'},
            },
        }

        data = self.vault.read_secret(1)

        self.assertEqual(data, {'secret': 'super_secret', 'other_factors': {'another': 'one'}})

    def test_read_secret_fails(self):
        self.mock_hvac.return_value.secrets.kv.v1.read_secret.side_effect = Exception('oops')

        with pytest.raises(VaultReadException):
            # token doesn't exist
            self.vault.read_secret(-1)
