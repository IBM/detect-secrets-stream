import json
from unittest import TestCase

import responses

from detect_secrets_stream.bp_lookup.bp_lookup import GHElookup
from detect_secrets_stream.util.conf import ConfUtil


class TestGHElookup(TestCase):

    def setUp(self):
        self.ghe_lookup = GHElookup()
        self.github_host = ConfUtil.load_github_conf()['host']

    @responses.activate
    def test_lookup_ghe_email(self):
        test_id = 'test-github-user'
        test_email = 'test-email'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{test_id}',
            body=json.dumps({'email': test_email}), status=200,
        )

        email = self.ghe_lookup.ghe_email_lookup(test_id)
        self.assertEqual(email, test_email)

    @responses.activate
    def test_lookup_ghe_email_with_at_sign_in_username(self):
        test_id = '@test-github-user'
        test_email = 'test-email'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{test_id[1:]}',
            body=json.dumps({'email': test_email}), status=200,
        )

        email = self.ghe_lookup.ghe_email_lookup(test_id)
        self.assertEqual(email, test_email)

    @responses.activate
    def test_lookup_ghe_email_401(self):
        test_id = 'test-github-user'
        test_email = ''
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{test_id}',
            status=401,
        )

        email = self.ghe_lookup.ghe_email_lookup(test_id)
        self.assertEqual(email, test_email)

    @responses.activate
    def test_lookup_ghe_email_no_email_returned(self):
        test_id = 'test-github-user'
        test_email = ''
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{test_id}',
            body=json.dumps({'oof': 'no email'}), status=200,
        )

        email = self.ghe_lookup.ghe_email_lookup(test_id)
        self.assertEqual(email, test_email)

    @responses.activate
    def test_ghe_author_committer_lookup(self):
        test_repo = 'test-owner/test-repo'
        test_commit = 'abc123'

        test_response = {
            'commit': {
                'author': {
                    'name': 'author-name',
                    'email': 'author-email@test.com',
                },
                'committer': {
                    'name': 'committer-name',
                    'email': 'committer-email@test.com',
                },
            },
        }
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{test_repo}/commits/{test_commit}',
            body=json.dumps(test_response), status=200,
        )

        author_name, author_email, committer_name, committer_email = \
            self.ghe_lookup.ghe_author_committer_lookup(test_repo, test_commit)
        self.assertEqual(author_name, 'author-name')
        self.assertEqual(author_email, 'author-email@test.com')
        self.assertEqual(committer_name, 'committer-name')
        self.assertEqual(committer_email, 'committer-email@test.com')

    @responses.activate
    def test_ghe_author_committer_lookup_401(self):
        test_repo = 'test-owner/test-repo'
        test_commit = 'abc123'

        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{test_repo}/commits/{test_commit}',
            status=401,
        )

        author_name, author_email, committer_name, committer_email = \
            self.ghe_lookup.ghe_author_committer_lookup(test_repo, test_commit)
        self.assertEqual(author_name, '')
        self.assertEqual(author_email, '')
        self.assertEqual(committer_name, '')
        self.assertEqual(committer_email, '')
