import requests
from ..util.conf import ConfUtil
from .base_vault_backend import BaseVaultBackend
from .vault_read_exception import VaultReadException
from ibm_cloud_sdk_core import ApiException, read_external_sources
import os
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

            # Set secrets manager parameters
            global sm_params
            sm_params = ConfUtil.load_sm_conf()

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
        token_name = str(token_id) if sm_params['SECRET_GROUP_NAME'] == 'DSS-Prod' else f'DSS-TEST-{str(token_id)}'
        secret_prototype_created = {
                'description': 'Secret Found in DSS',
                'labels': ['dss', sm_params['LABEL']],
                #'name': str(token_id),
                'name': token_name,
                'secret_group_id': sm_params['SECRET_GROUP_ID'], #ID of the DSS Group (TBC)
                'secret_type': 'kv',
                'data': secret_dict,
        }
        #Look to see if the secret exists
        read_status = 0 
        return_response = requests.Response()
        #If there's nothing in the secret we are not going to write it (for now)
        if secret == "":
            return_response.status_code=201
            return return_response
        
        try:
            print('attempting to read secret')
            read_response = secrets_manager_service.get_secret_by_name_type(
                    secret_type = 'kv',
                    name = token_name, 
                    secret_group_name = sm_params['SECRET_GROUP_NAME']
                )
            result = read_response.get_result()
            read_status = read_response.status_code
        except:
            pass
        if read_status == 200:
            secret_prototype_updated = {
                'data': secret_dict,
            }
            try:
                update_response = secrets_manager_service.create_secret_version(
                secret_id=result['id'],
                secret_version_prototype=secret_prototype_updated,
                ) 
                
                return_response.status_code = update_response.status_code
            except Exception:
                raise VaultReadException('Error updating secret to Secrets Manager. Something is wrong')
    
        else:
            try:
                create_response = secrets_manager_service.create_secret(
                        secret_prototype=secret_prototype_created,
                    )
                # Creating a response type object to put the status code in 
                return_response.status_code = create_response.status_code
            except Exception:
                raise VaultReadException('Error writing secret to Secrets Manager. Something is wrong')

        return return_response  
    
    def read_secret(self, token_id: int):
        """ Reads the secret at the given path from vault.
        Accepts: token_id: int, corresponds with the token_id in database
        Returns: dict containing secret, potentially other factors.
        Throws: VaultReadException if secret not in vault or other error encountered. """
        token_name = str(token_id) if sm_params['SECRET_GROUP_NAME'] == 'DSS-Prod' else f'DSS-TEST-{str(token_id)}'
        try:
            # begin-get_secret for the ID we got earlier 
            response = secrets_manager_service.get_secret_by_name_type(
                secret_type = 'kv',
                name = token_name, 
                secret_group_name = sm_params['SECRET_GROUP_NAME']
            )
            secret = response.get_result()
            # end-get_secret

        except Exception:
            raise VaultReadException('Error reading secret from Secrets Manager. Secret might not be in Secrets Manager.') 
        else:
            return secret['data']