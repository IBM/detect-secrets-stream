import logging
import os
from base64 import b64encode
from hashlib import sha256

import requests
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.github_enterprise import GheDetector

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.github_client.github import GitHub
from detect_secrets_stream.util.conf import ConfUtil
from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class GHEValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.ghe_instance = ConfUtil.load_github_conf()['host']

    @staticmethod
    def secret_type_name():
        # Use the secret type name prior to 0.13.1+ibm.47.dss
        # to remain backwards compatibility for downstream app consumption
        return 'GitHub Credentials'

    def validate(self, secret, other_factors=None):
        try:
            if self.ghe_instance:
                result = GheDetector(ghe_instance=self.ghe_instance).verify(secret)
            else:
                result = GheDetector().verify(secret)
            if result == VerifiedResult.VERIFIED_TRUE:
                return True
            elif result == VerifiedResult.VERIFIED_FALSE:
                return False
            else:
                raise ValidationException(
                    f'Failed to validate GHE token. {result} is neither VERIFIED_TRUE or VERIFIED_FALSE.',
                )
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to validate GHE token.',
            )

    def resolve_owner(self, secret, other_factors=None):
        '''
        Owner resolution follows priority like below
        1. email if set
        2. github login if email not set
        3. empty string
        '''
        url = ConfUtil.load_revoker_urls_conf()['github-owner-resolution']

        if type(secret) == bytes:
            secret = secret.decode('UTF-8')
        github = GitHub(token_list=[secret])
        response = github.get(url).json()
        result = ''
        if 'email' in response and response['email']:
            result = response['email']
        elif 'login' in response and response['login']:
            result = response['login']
        return result

    @staticmethod
    def hash_token(token: str) -> str:
        """ Matches GHE hashing. Encodes token to binary, hashes with sha256, then base64 encodes. """
        hasher = sha256()
        hasher.update(token.encode('ascii'))
        hashed_result = hasher.digest()
        return b64encode(hashed_result).decode('ascii')

    def revoke(self, secret, other_factors=None, secret_id=None):
        """ Revokes a GitHub secret. Returns Boolean representing whether or not
        revocation job was triggered. Throws RevocationError on exception. """
        try:
            revocation_endpoint = ConfUtil.load_revoker_urls_conf()['github-revocation']
            headers = {'Content-Type': 'application/json'}
            with open(os.getenv('GHE_REVOCATION_TOKEN_FILENAME')) as file:
                cred = file.read().rstrip('\n')
                params = {'token': cred}
            json = {'hash': self.hash_token(secret)}
            response = requests.post(revocation_endpoint, headers=headers, params=params, json=json)
            response.raise_for_status()
            jobsreslist = [v for v in response.json()['jobs'].values()]
            return jobsreslist[0]['triggered'] is True
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f'Unexpected request exception while revoking token. Error {e}', exc_info=1,
            )
            raise RevocationException('Failed to revoke GitHub token.')
        except Exception as e:
            self.logger.error(
                f'Unexpected error while revoking token. Error {e}', exc_info=1,
            )
            raise RevocationException('Failed to revoke GitHub token.')
