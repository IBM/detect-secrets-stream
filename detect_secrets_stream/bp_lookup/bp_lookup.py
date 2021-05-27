#!/usr/bin/python
import json
import logging

from ..github_client.github import GitHub
from ..util.conf import ConfUtil


class GHElookup():

    def __init__(self, github=GitHub()):
        self.logger = logging.getLogger(__name__)
        self.github = github
        self.github_host = ConfUtil.load_github_conf()['host']

    def ghe_email_lookup(self, ghe_id):
        """ looks up user email given a GHE short handle """
        try:
            if ghe_id[0] == '@':
                ghe_id = ghe_id[1:]
            ghe_users_url = f'https://{self.github_host}/api/v3/users/{ghe_id}'
            resp = self.github.get(
                url=ghe_users_url,
            )
            resp.raise_for_status()
            ghe_user_results = json.loads(resp.text)
            self.gheEmail = ghe_user_results['email'].lower()
            return self.gheEmail
        except Exception:
            self.logger.error(
                f'Failed to lookup email address for {ghe_id}.',
                exc_info=1,
            )
            return ''

    def ghe_author_committer_lookup(self, repo, commit):
        """ looks up author/committer names and emails given repo slug and commit """
        try:
            ghe_commit_url = f'https://{self.github_host}/api/v3/repos/{repo}/commits/{commit}'
            resp = self.github.get(
                url=ghe_commit_url,
            )
            resp.raise_for_status()
            ghe_commit_results = json.loads(resp.text)
            self.authorName = ghe_commit_results['commit']['author']['name']
            self.authorEmail = ghe_commit_results['commit']['author']['email']
            self.committerName = ghe_commit_results['commit']['committer']['name']
            self.committerEmail = ghe_commit_results['commit']['committer']['email']
            return (self.authorName, self.authorEmail, self.committerName, self.committerEmail)
        except Exception:
            self.logger.error(
                f'Failed to lookup author/commiter info for commit {commit} in repo {repo}.',
                exc_info=1,
            )
            return ('', '', '', '')
