import logging
# import os

# import hvac
import requests
from ..util.conf import ConfUtil
from .base_vault_backend import BaseVaultBackend
from .vault_read_exception import VaultReadException

from ibm_cloud_sdk_core import ApiException, read_external_sources
import os
import pytest
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

config_file = 'secrets_manager_v2.env'

secrets_manager_service = None

config = None

class Vault(BaseVaultBackend):

    def __init__(self):

        global secrets_manager_service
        print('Starting Setting Up')
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            # begin-common

            secrets_manager_service = SecretsManagerV2.new_instance(
            )
            print('Setting Up')
            # end-common
            assert secrets_manager_service is not None

            # Load the configuration
            global config
            config = read_external_sources(SecretsManagerV2.DEFAULT_SERVICE_NAME)
        
        print('Setup complete.')

        # self.logger = logging.getLogger(__name__)

        # vault_conf = ConfUtil.load_vault_conf()
        # self.token_path = vault_conf['token_path']
        # self.mount_point = vault_conf['mount_point']
        # self.client = hvac.Client(url=vault_conf['gd_vault_url'], verify=vault_conf.get('gd_vault_verify', True))
        # self.client.auth.approle.login(
        #     role_id=vault_conf['gd_vault_approle_id'],
        #     secret_id=vault_conf['gd_vault_secret_id'],
        # )

        # self.logger.info(f'vault: client.is_authenticated(): {self.client.is_authenticated()}')
    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )
    @needscredentials
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
        secret_name = "DSS-"+str(token_id)+"-DSS"
        secret_prototype_created = {
                'custom_metadata': {'metadata_custom_key':'metadata_custom_value'},
                'description': 'Description of my arbitrary secret.',
                'labels': ['dss', 'us-south'],
                'name': secret_name,
                'secret_group_id': '1262ffb2-8921-3442-2e2b-cd35d4a1c838',
                'secret_type': 'kv',
                'data': secret_dict,
                'version_custom_metadata': {'custom_version_key':'custom_version_value'}, # will need to add stuff for token other factors here I think
        }
        # create_response = self.client.secrets.kv.v1.create_or_update_secret(
        #     mount_point=self.mount_point,
        #     path=os.path.join(self.token_path, str(token_id)),
        #     secret=secret_dict,
        # )
        try:
            response = secrets_manager_service.create_secret(
                    secret_prototype=secret_prototype_created,
                )
            secret = response.get_result()
            r = requests.Response()
            r.status_code = response.status_code
            print(json.dumps(secret, indent=2))
        except ApiException as e:
            pytest.fail(str(e))

        return r  #!! will need to be revisted (need to check the return stuff) !!
    
    def read_secret(self, token_id: int):
        """ Reads the secret at the given path from vault.
        Accepts: token_id: int, corresponds with the token_id in database
        Returns: dict containing secret, potentially other factors.
        Throws: VaultReadException if secret not in vault or other error encountered.
        """
        ##OLD CODE
        # try:
        #     read_response = self.client.secrets.kv.v1.read_secret(
        #         os.path.join(self.token_path, str(token_id)),
        #         mount_point=self.mount_point,
        #     )
        # except Exception:
        #     raise VaultReadException('Error reading secret from vault. Secret might not be in vault.')
        # else:
            # return read_response['data']
        try:
            print('\nlist_secrets() result:') 
            # begin-list_secrets to and searching for the tokenID
            all_results = []
            secret_name = "DSS-"+str(token_id)+"-DSS"
            pager = SecretsPager(
                client=secrets_manager_service,
                limit=10,
                sort='created_at',  #sorting by created at (we expect only 1 secret)
                search=secret_name,     # searching for the secret name 
                groups=['1262ffb2-8921-3442-2e2b-cd35d4a1c838'],
            )
            while pager.has_next():
                next_page = pager.get_next()
                assert next_page is not None
                all_results.extend(next_page)

            # print(json.dumps(all_results, indent=2))
            # print(all_results)
            # print(all_results[0])
            found_secret = all_results[0]   # !! Right now we are expecting only 1 to return, need to assert this
            print('Name of the secret is', found_secret['name'])
            print('The ID of the secret is', found_secret['id'])
            ibm_cloud_secret_id = found_secret['id']
        except Exception:
             raise VaultReadException('Error reading secret from vault. Secret might not be in vault.')
        # except ApiException as e:
        #     pytest.fail(str(e))

        try:
            print('\nget_secret() result:')
            # begin-get_secret for the ID we got earlier 
            response = secrets_manager_service.get_secret(
                id=ibm_cloud_secret_id,
            )
            secret = response.get_result() 

            # print(json.dumps(secret, indent=2))
            print(secret['data'])
            # end-get_secret

        except Exception:
             raise VaultReadException('Error reading secret from vault. Secret might not be in vault.')
        # except ApiException as e:
        #     pytest.fail(str(e))
        else:
            return secret['data']  # !! need to revisit what we have here, we will need to determine the other_factors
        