import logging
import os

import hvac

from ..util.conf import ConfUtil
from .base_vault_backend import BaseVaultBackend
from .vault_read_exception import VaultReadException


class Vault(BaseVaultBackend):

    def __init__(self):

        self.logger = logging.getLogger(__name__)

        vault_conf = ConfUtil.load_vault_conf()
        self.token_path = vault_conf['token_path']
        self.mount_point = vault_conf['mount_point']
        self.client = hvac.Client(url=vault_conf['gd_vault_url'], verify=vault_conf.get('gd_vault_verify', True))
        self.client.auth.approle.login(
            role_id=vault_conf['gd_vault_approle_id'],
            secret_id=vault_conf['gd_vault_secret_id'],
        )

        self.logger.info(f'vault: client.is_authenticated(): {self.client.is_authenticated()}')

    def create_or_update_secret(self, token_id: int, secret: str, other_factors=None):
        """ Creates secret if doesn't exist, updates it if it does.

        Accepts: token_id: int, corresponds with the token_id in database
                 secret: str, the secret to write
                 other_factors: dict, secondary multifactors to write
        Returns: requests.Response.status_code returned from vault. """

        secret_dict = {
            'secret': secret,
            'other_factors': other_factors,
        }
        create_response = self.client.secrets.kv.v1.create_or_update_secret(
            mount_point=self.mount_point,
            path=os.path.join(self.token_path, str(token_id)),
            secret=secret_dict,
        )
        return create_response

    def read_secret(self, token_id: int):
        """ Reads the secret at the given path from vault.
        Accepts: token_id: int, corresponds with the token_id in database
        Returns: dict containing secret, potentially other factors.
        Throws: VaultReadException if secret not in vault or other error encountered.
        """
        try:
            read_response = self.client.secrets.kv.v1.read_secret(
                os.path.join(self.token_path, str(token_id)),
                mount_point=self.mount_point,
            )
        except Exception:
            raise VaultReadException('Error reading secret from vault. Secret might not be in vault.')
        else:
            return read_response['data']
