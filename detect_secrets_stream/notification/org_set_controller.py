import logging

import yaml
from requests.exceptions import HTTPError

from ..github_client.github import GitHub
from ..util.conf import ConfUtil


class OrgSetController(object):

    def __init__(self, admin_config=ConfUtil.load_github_conf()['admin_config']):
        self._logger = logging.getLogger(__name__)
        # {<org_name>: {'security_focal_emails': [<email_1>,...,<email_n>]}}
        self._org_mappings = {}
        self._github_host = ConfUtil.load_github_conf()['host']
        self._admin_config = admin_config
        self.load_org_sets_from_config_files()

    @property
    def org_mappings(self):
        return self._org_mappings

    def get_security_focal_emails_for_repo(self, repo_slug):
        """ Given repo slug, returns security focal emails for the encompassing org/org set.
        Returns set of strings. """
        security_focal_emails = set()
        org_name = repo_slug.split('/')[0]
        if org_name in self._org_mappings:
            security_focal_emails = self._org_mappings[org_name]['security-focal-emails'].copy()
        return security_focal_emails

    def get_org_set_names_for_repo(self, repo_slug):
        """ Given the repo slug, returns the name(s) of the org sets the repo
        belongs to (i.e. the config filename without the .yaml extension)
        Returns set of strings """
        org_set_names = set()
        if repo_slug:
            org_name = repo_slug.split('/')[0]
            if org_name in self._org_mappings:
                org_set_names = self._org_mappings[org_name]['org-set-names'].copy()
        return org_set_names

    def load_org_sets_from_config_files(self):
        """ Populates dict self._org_mappings with the following format:
        { # dict
            'org_name_1': { # dict
                    'security-focal-emails': { # set
                            "security_focal_emails1",
                            "security_focal_emails2",
                            ...
                        }
                    'org-set-names': { # set
                            "org_set_name_1",
                            "org_set_name_2",
                            ...
                        }
                }
            'org_name_2': {...}
        }
        """
        try:
            headers = {'Accept': 'application/json'}
            github = GitHub()
            response = github.get(url=self._admin_config, headers=headers).json()
            for item in response:
                if item['type'] == 'file':
                    filename = item['name']
                    config_file_contents = yaml.safe_load(github.get(item['download_url']).text)
                    if 'organizations' not in config_file_contents or \
                            'security-focal-emails' not in config_file_contents:
                        self._logger.info(f'Encountered misformatted config file: {filename}')
                        continue
                    else:
                        organization_names = config_file_contents['organizations']
                        security_focal_emails = config_file_contents['security-focal-emails']
                        org_set_name = filename.split('.')[0]
                        for org_name in organization_names:
                            if org_name in self._org_mappings:
                                self._org_mappings[org_name]['security-focal-emails'].\
                                    update(security_focal_emails)
                                self._org_mappings[org_name]['org-set-names'].add(org_set_name)
                            else:
                                self._org_mappings[org_name] = {
                                    'security-focal-emails': set(security_focal_emails),
                                    'org-set-names': set([org_set_name]),
                                }
        except HTTPError as http_err:
            self._logger.error(
                'HTTP Error encountered while loading org set information from github',
            )
            raise http_err
        except Exception as e:
            self._logger.error(
                'Error loading org set information from config files',
            )
            raise e
