import json
from unittest import TestCase
from unittest.mock import patch

import pytest
import responses

from detect_secrets_stream.github_client.github import GitHub
from detect_secrets_stream.github_client.installation_id_request_exception import InstallationIDRequestException
from detect_secrets_stream.scan_worker.commitparser import CommitParser
from detect_secrets_stream.util.conf import ConfUtil


class CommitParserTest (TestCase):

    def setUp(self):
        self.commitparser = CommitParser()
        self.github_host = ConfUtil.load_github_conf()['host']

    @patch('detect_secrets_stream.github_client.github.GitHub.get')
    @responses.activate
    def test_get_intermediate_commits(self, mock_github_get):
        commit = '3'
        repo = 'test-repo'
        v3_response = {'node_id': 1}
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                repo, commit,
            ),
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v3_response), status=200,
        )

        v4_response = {
            'data': {
                'node': {
                    'history': {
                        'totalCount': 3,
                        'pageInfo': {'endCursor': 1},
                        'edges': [
                            {'node': {'oid': 3}},
                            {'node': {'oid': 2}},
                            {'node': {'oid': 1}},
                        ],
                    },
                },
            },
        }
        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql',
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v4_response), status=200,
        )

        commits = self.commitparser.get_intermediate_commits(repo, 1, 3, 'true')
        mock_github_get.assert_called()
        self.assertIn(1, commits)
        self.assertIn(2, commits)
        self.assertIn(3, commits)

    @patch('detect_secrets_stream.github_client.github_app.GitHubApp.get_github_client')
    @responses.activate
    def test_get_intermediate_commits_private_repo(self, mock_github_app_get_private_github_client):
        mock_github_app_get_private_github_client.return_value = GitHub()

        commit = '3'
        repo = 'test-repo'
        v3_response = {'node_id': 1}
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                repo, commit,
            ),
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v3_response), status=200,
        )

        v4_response = {
            'data': {
                'node': {
                    'history': {
                        'totalCount': 3,
                        'pageInfo': {'endCursor': 1},
                        'edges': [
                            {'node': {'oid': 3}},
                            {'node': {'oid': 2}},
                            {'node': {'oid': 1}},
                        ],
                    },
                },
            },
        }
        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql',
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v4_response), status=200,
        )

        commits = self.commitparser.get_intermediate_commits(repo, 1, 3, 'false')
        mock_github_app_get_private_github_client.assert_called()
        self.assertIn(1, commits)
        self.assertIn(2, commits)
        self.assertIn(3, commits)

    @patch('detect_secrets_stream.github_client.github_app.GitHubApp.get_github_client')
    @responses.activate
    def test_get_intermediate_commits_private_repo_app_not_installed(
        self, mock_github_app_get_private_github_client,
    ):
        repo = 'test-repo'
        mock_github_app_get_private_github_client.side_effect = InstallationIDRequestException()

        with pytest.raises(InstallationIDRequestException):
            self.commitparser.get_intermediate_commits(repo, 1, 3, 'false')

    @responses.activate
    def test_get_intermediate_commits_multiple_pages(self):
        self.commitparser.page_length = 2
        commit = '4'
        repo = 'test-repo'
        v3_response = {'node_id': 1}
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                repo, commit,
            ),
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v3_response), status=200,
        )

        v4_response_1 = {
            'data': {
                'node': {
                    'history': {
                        'totalCount': 4,
                        'pageInfo': {'endCursor': 3},
                        'edges': [
                            {'node': {'oid': 4}},
                            {'node': {'oid': 3}},
                        ],
                    },
                },
            },
        }
        v4_response_2 = {
            'data': {
                'node': {
                    'history': {
                        'totalCount': 4,
                        'pageInfo': {'endCursor': 1},
                        'edges': [
                            {'node': {'oid': 2}},
                            {'node': {'oid': 1}},
                        ],
                    },
                },
            },
        }
        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql',
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v4_response_1), status=200,
        )
        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql',
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v4_response_2), status=200,
        )

        commits = self.commitparser.get_intermediate_commits(repo, 2, 4, 'true')
        self.assertIn(2, commits)
        self.assertIn(3, commits)
        self.assertIn(4, commits)
        self.assertNotIn(1, commits)

    @patch('logging.Logger.error')
    @responses.activate
    def test_get_intermediate_commits_bad_v3_request(self, mock_error):
        commit = '3'
        repo = 'test-repo'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                repo, commit,
            ),
            headers={'X-RateLimit-Remaining': '5'}, status=404,
        )
        commits = self.commitparser.get_intermediate_commits(repo, 1, 3, 'true')
        mock_error.assert_called()
        assert len(commits) == 0

    @patch('logging.Logger.error')
    @responses.activate
    def test_get_intermediate_commits_bad_v4_request(self, mock_error):
        commit = '3'
        repo = 'test-repo'
        v3_response = {'node_id': 1}
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                repo, commit,
            ),
            headers={'X-RateLimit-Remaining': '5'}, body=json.dumps(v3_response), status=200,
        )
        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql',
            headers={'X-RateLimit-Remaining': '5'}, status=404,
        )

        commits = self.commitparser.get_intermediate_commits(repo, 1, 3, 'true')
        mock_error.assert_called()
        assert len(commits) == 0
