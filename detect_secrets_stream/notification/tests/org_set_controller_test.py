from unittest import TestCase

import pytest
import responses
import yaml
from mock import patch
from requests.exceptions import HTTPError

from ...util.conf import ConfUtil
from ..org_set_controller import OrgSetController


class TestOrgSetController(TestCase):

    @patch('detect_secrets_stream.notification.org_set_controller.OrgSetController.load_org_sets_from_config_files')
    def setUp(self, mock_load_org_set):
        self.org_set_controller = OrgSetController()
        self.github_host = ConfUtil.load_github_conf()['host']
        self.admin_config = ConfUtil.load_github_conf()['admin_config']
        self.email_domain = 'test.test'

    def test_admin_config_contains_gh_host(self):
        assert self.github_host in self.admin_config

    def test_get_security_focal_emails_for_repo(self):
        test_repo_slug = 'test-org/test-repo'
        self.org_set_controller._org_mappings = {
            'test-org':
            {
                'security-focal-emails':
                    {f'focal1@{self.email_domain}', f'focal2@{self.email_domain}', f'focal3@{self.email_domain}'},
                'org-set-names': {'orgset1'},
            },
            'not-test-org':
            {
                'security-focal-emails': {f'otherfocal@{self.email_domain}'},
                'org-set-names': {'orgset1'},
            },
        }
        emails = self.org_set_controller.get_security_focal_emails_for_repo(test_repo_slug)
        assert emails == {f'focal1@{self.email_domain}', f'focal2@{self.email_domain}', f'focal3@{self.email_domain}'}

        self.org_set_controller._org_mappings = {}
        emails = self.org_set_controller.get_security_focal_emails_for_repo(test_repo_slug)
        assert emails == set()

    def test_get_org_set_names_for_repo(self):
        test_repo_slug = 'test-org/test-repo'
        self.org_set_controller._org_mappings = {
            'test-org':
            {
                'security-focal-emails':
                    {f'focal1@{self.email_domain}', f'focal2@{self.email_domain}', f'focal3@{self.email_domain}'},
                'org-set-names': {'orgset1'},
            },
            'not-test-org':
            {
                'security-focal-emails': {f'otherfocal@{self.email_domain}'},
                'org-set-names': {'orgset1'},
            },
        }
        org_set_name = self.org_set_controller.get_org_set_names_for_repo(test_repo_slug)
        assert org_set_name == {'orgset1'}

        self.org_set_controller._org_mappings = {}
        org_set_name = self.org_set_controller.get_org_set_names_for_repo(test_repo_slug)
        assert org_set_name == set()

    @responses.activate
    def test_load_org_sets_from_config_files(self):
        responses.add(
            responses.GET,
            f'{self.admin_config}',
            status=200,
            body=(
                '[{"name": "config1.yaml", "type": "file", '
                f'"download_url": "https://{self.github_host}/download/some/file"}},'
                '{"name": "config2.yaml", "type": "file", '
                f'"download_url": "https://{self.github_host}/download/another/file"}}]'
            ),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/some/file',
            status=200,
            body=yaml.dump({
                'organizations': ['not-test-org-name', 'a-different-org'],
                'security-focal-emails': [f'sec1@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/another/file',
            status=200,
            body=yaml.dump({
                'organizations': ['test-org-name', 'another-different-org'],
                'security-focal-emails': [f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        self.org_set_controller.load_org_sets_from_config_files()
        assert self.org_set_controller.org_mappings == {
            'not-test-org-name':
            {
                'security-focal-emails': {f'sec1@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config1'},
            },
            'a-different-org':
            {
                'security-focal-emails': {f'sec1@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config1'},
            },
            'test-org-name':
            {
                'security-focal-emails': {f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config2'},
            },
            'another-different-org':
            {
                'security-focal-emails': {f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config2'},
            },
        }

    @responses.activate
    def test_load_org_sets_from_config_files_org_in_multiple_sets(self):
        responses.add(
            responses.GET,
            f'{self.admin_config}',
            status=200,
            body=(
                '[{"name": "config1.yaml", "type": "file", '
                '"download_url": "https://%s/download/some/file"},' % self.github_host +
                '{"name": "config2.yaml", "type": "file", '
                '"download_url": "https://%s/download/another/file"}]' % self.github_host
            ),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/some/file',
            status=200,
            body=yaml.dump({
                'organizations': ['test-org-name', 'a-different-org'],
                'security-focal-emails':
                    [f'sec1@{self.email_domain}', f'sec3@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/another/file',
            status=200,
            body=yaml.dump({
                'organizations': ['test-org-name', 'another-different-org'],
                'security-focal-emails':
                    [f'sec2@{self.email_domain}', f'sec3@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        self.org_set_controller.load_org_sets_from_config_files()
        assert self.org_set_controller.org_mappings == {
            'a-different-org':
            {
                'security-focal-emails':
                    {f'sec1@{self.email_domain}', f'sec3@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config1'},
            },
            'test-org-name':
            {
                'security-focal-emails': {
                    f'sec1@{self.email_domain}', f'sec3@{self.email_domain}', f'admin2@{self.email_domain}',
                    f'sec2@{self.email_domain}', f'admin2@{self.email_domain}',
                },
                'org-set-names': {'config1', 'config2'},
            },
            'another-different-org':
            {
                'security-focal-emails':
                    {f'sec2@{self.email_domain}', f'sec3@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config2'},
            },
        }

    @responses.activate
    def test_load_org_sets_from_config_files_one_config_is_misformatted(self):
        responses.add(
            responses.GET,
            f'{self.admin_config}',
            status=200,
            body=(
                '[{"name": "config1.yaml", "type": "file", '
                '"download_url": "https://%s/download/some/file"},' % self.github_host +
                '{"name": "config2.yaml", "type": "file", '
                '"download_url": "https://%s/download/another/file"}]' % self.github_host
            ),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/some/file',
            status=200,
            body=yaml.dump({
                'not-organizations': ['not-test-org-name', 'a-different-org'],
                'not-security-focal-emails': [f'sec1@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        responses.add(
            responses.GET,
            f'https://{self.github_host}/download/another/file',
            status=200,
            body=yaml.dump({
                'organizations': ['test-org-name', 'another-different-org'],
                'security-focal-emails': [f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'],
            }),
        )
        self.org_set_controller.load_org_sets_from_config_files()
        assert self.org_set_controller.org_mappings == {
            'test-org-name':
            {
                'security-focal-emails': {f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config2'},
            },
            'another-different-org':
            {
                'security-focal-emails': {f'sec2@{self.email_domain}', f'admin2@{self.email_domain}'},
                'org-set-names': {'config2'},
            },
        }

    @responses.activate
    def test_load_org_sets_from_config_files_bad_request(self):
        responses.add(
            responses.GET,
            f'{self.admin_config}',
            status=404,
        )
        with pytest.raises(HTTPError):
            self.org_set_controller.load_org_sets_from_config_files()
