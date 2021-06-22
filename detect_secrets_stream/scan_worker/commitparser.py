import json
import logging
from urllib.error import HTTPError

from ..github_client.github import GitHub
from ..github_client.github_app import GitHubApp
from ..github_client.installation_id_request_exception import InstallationIDRequestException
from detect_secrets_stream.util.conf import ConfUtil


class CommitParser(object):

    def __init__(self, page_length=25, max_commits_to_pull=250):
        self.logger = logging.getLogger(__name__)
        self.page_length = page_length
        self.max_commits_to_pull = max_commits_to_pull
        self.github_public_client = GitHub()
        self.github_app = GitHubApp()
        self.github_host = ConfUtil.load_github_conf()['host']

    def _get_page_of_commits(self, last_commit_node_id, page_length, after=None, github_client=None):
        """ Get a page of commits from the GitHub Graphql API (v4). The page
        will consist of [page_length] # of commits, starting from [last_commit_node_id]
        and working backwards in time. Set [after] to the endCursor from the previous
        request, if pulling additional pages in a subsequent call to this function. """
        if github_client is None:
            github_client = self.github_public_client

        try:
            if after:
                after = ", after: \"%s\"" % after
            else:
                after = ''
            query = """
            {
                node(id: "%s") {
                    ... on Commit {
                        id
                        history(first: %s%s) {
                            totalCount
                            pageInfo {
                                startCursor
                                hasNextPage
                                endCursor
                            }
                            edges {
                                node {
                                    oid
                                }
                            }
                        }
                    }
                }
            }
            """ % (last_commit_node_id, page_length, after)
            response = github_client.post(
                url=f'https://api.{self.github_host}/graphql', body=json.dumps(
                    {'query': query},
                ), headers={'Content-type': 'application/json'},
            )
            self.logger.info(response.headers['X-RateLimit-Remaining'])
            return response.json()
        except Exception:
            self.logger.error(
                'Exception in retrieving page of commits.', exc_info=1,
            )

    def get_intermediate_commits(self, repo_slug, first_commit, last_commit, repo_public):
        """ Given the repo slug and the first and last commit hashes in the push,
        return the commit hashes of the intermediate commits """
        # get node ID for the last commit using rest API
        commits = []
        github = self.github_public_client
        if repo_public == 'false':
            try:
                github = self.github_app.get_github_client(repo_slug)
            except InstallationIDRequestException as e:
                self.logger.error(
                    (
                        f'Failed to retrieve installation ID for repo {repo_slug}. '
                        'App is likely not installed on private repo.'
                    ),
                    exc_info=1,
                )
                raise e
        try:
            response = github.get(
                url=f'https://{self.github_host}/api/v3/repos/%s/commits/%s' % (
                    repo_slug, last_commit,
                ), headers={'Content-type': 'application/json'},
            )
            last_commit_node_id = response.json()['node_id']

            page_length = self.page_length
            page = self._get_page_of_commits(last_commit_node_id, page_length, github_client=github)
            total_commits = page['data']['node']['history']['totalCount']

            reached_first_commit = False
            commits_pulled = 0
            while not reached_first_commit \
                    and commits_pulled < self.max_commits_to_pull \
                    and commits_pulled < total_commits:
                commits_pulled += page_length
                for commit in page['data']['node']['history']['edges']:
                    commit_hash = commit['node']['oid']
                    commits.append(commit_hash)
                    if commit_hash == first_commit:
                        reached_first_commit = True
                        break
                end_cursor = page['data']['node']['history']['pageInfo']['endCursor']
                page = self._get_page_of_commits(
                    last_commit_node_id, page_length, after=end_cursor, github_client=github,
                )
        except HTTPError:
            self.logger.error(
                'Exception getting commit node_id from GitHub V3 API.', exc_info=1,
            )
        except Exception:
            self.logger.error(
                'Exception getting intermediate commits.', exc_info=1,
            )

        return commits
