import logging
import requests
from ..util.conf import ConfUtil
from .base_vault_backend import BaseVaultBackend
from .vault_read_exception import VaultReadException
from ibm_cloud_sdk_core import ApiException, read_external_sources
import os
import pytest
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

config_file = os.environ['GD_VAULT_CONF']
secrets_manager_service = None
config = None

class Vault(BaseVaultBackend):

    def __init__(self):

        global secrets_manager_service
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file
            # begin-common
            secrets_manager_service = SecretsManagerV2.new_instance(
            )
            # end-common
            assert secrets_manager_service is not None

            # Load the configuration
            global config
            config = read_external_sources(SecretsManagerV2.DEFAULT_SERVICE_NAME)
#function to throw issues if there's no configuration available
    # needscredentials = pytest.mark.skipif(
    #     not os.path.exists(config_file), reason="External configuration not available, skipping..."
    # )
    # @needscredentials
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
        # Creating a new secret name to ensure theres no collisions in searching
        secret_name = "DSS-"+str(token_id)+"-DSS"
        secret_prototype_created = {
                'description': 'Secret Found in DSS',
                'labels': ['dss', 'production'],
                'name': secret_name,
                'secret_group_id': '1262ffb2-8921-3442-2e2b-cd35d4a1c838', #ID of the DSS Group (TBC)
                'secret_type': 'kv',
                'data': secret_dict,
        }
        try:
            create_response = secrets_manager_service.create_secret(
                    secret_prototype=secret_prototype_created,
                )
            # Creating a response type object to put the status code in 
            return_response = requests.Response()
            return_response.status_code = create_response.status_code
        except Exception:
             raise VaultReadException('Error writing secret to Secrets Manager. Something is wrong')

        return return_response  
    
    def read_secret(self, token_id: int):
        """ Reads the secret at the given path from vault.
        Accepts: token_id: int, corresponds with the token_id in database
        Returns: dict containing secret, potentially other factors.
        Throws: VaultReadException if secret not in vault or other error encountered.
        """
        try:
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
            all_results.extend(pager.get_next())
            if pager.has_next():
                raise VaultReadException('There was a collision in reading secrets from Secrets manager (more than one found)')
            
            found_secret = all_results[0] # Testing with naming convention ensures only 1 will return (max)
            ibm_cloud_secret_id = found_secret['id']
        except Exception:
             raise VaultReadException('Error listing secrets from Secrets Manager. Could be an issue with secret group.')
        
        try:
            # begin-get_secret for the ID we got earlier 
            response = secrets_manager_service.get_secret(
                id=ibm_cloud_secret_id,
            )
            secret = response.get_result()
            # end-get_secret

        except Exception:
            raise VaultReadException('Error reading secret from Secrets Manager. Secret might not be in Secrets Manager.') 
        else:
            return secret['data']