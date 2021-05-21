import logging
import os
import signal
import sys
import time

import prometheus_client as prom

from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import disconnect_db
from ..secret_corpus_db.gd_db_tools import get_token_count_by_type
from ..util.log_util import LogUtil


class DBMetrics(object):

    def __init__(self):
        self.query_interval = int(os.getenv('QUERY_INTERVAL', 60))
        self.prometheus_port = int(os.getenv('PROMETHEUS_PORT', 14269))
        self.logger = logging.getLogger(__name__)
        self.db_tokens_total = prom.Gauge(
            'db_tokens_total', 'Collected tokens counts from DB', ['type', 'state', 'visibility'],
        )
        self.percentage_remediated = prom.Gauge(
            'db_percentage_remediated', 'Percentage of total found tokens that have been remediated',
        )

    def start_prom_server(self):
        prom.start_http_server(self.prometheus_port)

    def get_state(self, is_live):
        if is_live is True:
            return 'live'
        elif is_live is False:
            return 'remediated'
        else:
            return 'unknown'

    def get_visibility(self, repo_public):
        if repo_public is True:
            return 'public'
        elif repo_public is False:
            return 'private'
        else:
            return 'unknown'

    def collect_metrics(self, db_conn):
        # {
        # "public": {
        #   'GHE': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   'DB2': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   }
        #  "private": {
        #   'GHE': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   'DB2': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   }
        #  "any": {
        #   'GHE': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   'DB2': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   }
        #  "unknown": {
        #   'GHE': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   'DB2': {"live": 1, "remediated": 2, "unknown": 0, "any": 3},
        #   }
        # }
        token_dict = {}
        token_dict['any'] = {}

        # [
        #   (tokenType, is_live, repo_public, count),
        #   (tokenType, is_live, repo_public, count),
        # ]
        token_by_type_list = get_token_count_by_type(db_conn)
        for token_type, is_live, repo_public, count in token_by_type_list:
            state = self.get_state(is_live)
            visibility = self.get_visibility(repo_public)
            if token_dict.get(visibility) is None:
                token_dict[visibility] = {}
            if token_dict[visibility].get(token_type) is None:
                token_dict[visibility][token_type] = {}
            if token_dict['any'].get(token_type) is None:
                token_dict['any'][token_type] = {}
            if token_dict['any'][token_type].get(state) is None:
                token_dict['any'][token_type][state] = 0
            token_dict[visibility][token_type][state] = count
            token_dict['any'][token_type][state] += count

        # variables for type=any (state)
        any_live_public = 0
        any_remediated_public = 0
        any_unknown_public = 0

        public_tokens = token_dict.get('public')
        if public_tokens:
            for token_type, token in public_tokens.items():
                type_any_count = 0
                for state, count in token.items():
                    # calculate state=any for each token type
                    type_any_count = type_any_count + count
                    self.db_tokens_total.labels(token_type, state, 'public').set(count)

                    # calculate for type=any, visibility=public
                    if state == 'live':
                        any_live_public = any_live_public + count
                    elif state == 'remediated':
                        any_remediated_public = any_remediated_public + count
                    elif state == 'unknown':
                        any_unknown_public = any_unknown_public + count

                token_dict['public'][token_type]['any'] = type_any_count
                self.db_tokens_total.labels(token_type, 'any', 'public').set(type_any_count)

        # generate metrics for type=any (public)
        any_any_public = any_live_public + any_remediated_public + any_unknown_public
        self.db_tokens_total.labels('any', 'live', 'public').set(any_live_public)
        self.db_tokens_total.labels('any', 'remediated', 'public').set(any_remediated_public)
        self.db_tokens_total.labels('any', 'unkwown', 'public').set(any_unknown_public)
        self.db_tokens_total.labels('any', 'any', 'public').set(any_any_public)

        # variables for type=any (state)
        any_live_private = 0
        any_remediated_private = 0
        any_unknown_private = 0

        private_tokens = token_dict.get('private')
        if private_tokens:
            for token_type, token in private_tokens.items():
                type_any_count = 0
                for state, count in token.items():
                    # calculate state=any for each token type
                    type_any_count = type_any_count + count
                    self.db_tokens_total.labels(token_type, state, 'private').set(count)

                    # calculate for type=any, visibility=private
                    if state == 'live':
                        any_live_private = any_live_private + count
                    elif state == 'remediated':
                        any_remediated_private = any_remediated_private + count
                    elif state == 'unknown':
                        any_unknown_private = any_unknown_private + count

                token_dict['private'][token_type]['any'] = type_any_count
                self.db_tokens_total.labels(token_type, 'any', 'private').set(type_any_count)

        # generate metrics for type=any (private)
        any_any_private = any_live_private + any_remediated_private + any_unknown_private
        self.db_tokens_total.labels('any', 'live', 'private').set(any_live_private)
        self.db_tokens_total.labels('any', 'remediated', 'private').set(any_remediated_private)
        self.db_tokens_total.labels('any', 'unkwown', 'private').set(any_unknown_private)
        self.db_tokens_total.labels('any', 'any', 'private').set(any_any_private)

        # variables for type=any (state)
        any_live_unknown = 0
        any_remediated_unknown = 0
        any_unknown_unknown = 0

        unknown_tokens = token_dict.get('unknown')
        if unknown_tokens:
            for token_type, token in unknown_tokens.items():
                type_any_count = 0
                for state, count in token.items():
                    # calculate state=any for each token type
                    type_any_count = type_any_count + count
                    self.db_tokens_total.labels(token_type, state, 'unknown').set(count)

                    # calculate for type=any, visibility=unknown
                    if state == 'live':
                        any_live_unknown = any_live_unknown + count
                    elif state == 'remediated':
                        any_remediated_unknown = any_remediated_unknown + count
                    elif state == 'unknown':
                        any_unknown_unknown = any_unknown_unknown + count

                token_dict['unknown'][token_type]['any'] = type_any_count
                self.db_tokens_total.labels(token_type, 'any', 'unknown').set(type_any_count)

        # generate metrics for type=any (unknown)
        any_any_unknown = any_live_unknown + any_remediated_unknown + any_unknown_unknown
        self.db_tokens_total.labels('any', 'live', 'unknown').set(any_live_unknown)
        self.db_tokens_total.labels('any', 'remediated', 'unknown').set(any_remediated_unknown)
        self.db_tokens_total.labels('any', 'unkwown', 'unknown').set(any_unknown_unknown)
        self.db_tokens_total.labels('any', 'any', 'unknown').set(any_any_unknown)

        # metrics for visibility=any
        public_and_private_tokens = token_dict.get('any')
        if public_and_private_tokens:
            for token_type, token in public_and_private_tokens.items():
                type_any_count = 0
                for state, count in token.items():
                    # calculate state=any for each token type
                    type_any_count = type_any_count + count
                    self.db_tokens_total.labels(token_type, state, 'any').set(count)

                token_dict['any'][token_type]['any'] = type_any_count
                self.db_tokens_total.labels(token_type, 'any', 'any').set(type_any_count)

        any_any_any = any_any_public + any_any_private + any_any_unknown
        any_live = any_live_public + any_live_private + any_live_unknown
        any_remediated = any_remediated_public + any_remediated_private + any_remediated_unknown
        any_unknown = any_unknown_public + any_unknown_private + any_unknown_unknown
        self.db_tokens_total.labels('any', 'live', 'any').set(any_live)
        self.db_tokens_total.labels('any', 'remediated', 'any').set(any_remediated)
        self.db_tokens_total.labels('any', 'unkwown', 'any').set(any_unknown)
        self.db_tokens_total.labels('any', 'any', 'any').set(any_any_any)

        if any_any_any != 0:
            self.percentage_remediated.set((any_remediated/any_any_any)*100)
        else:
            self.percentage_remediated.set(0)

    def start_collection(self):
        # Fail to connect should raise exception
        db_conn = connect_db()
        while True:
            self.collect_metrics(db_conn)
            time.sleep(self.query_interval)

    def terminate(self, signum, frame):
        self.logger.info(
            f'Signal {signum} has been received, cleaning up and exiting.',
        )
        try:
            disconnect_db(self.db_conn)
            sys.exit(0)
        except Exception:
            self.logger.warning('Fail to disconnect, ignore', exc_info=1)
            sys.exit(1)


if __name__ == '__main__':
    LogUtil.set_root_logger_json()

    db_metrics = DBMetrics()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, db_metrics.terminate)
    db_metrics.start_prom_server()
    db_metrics.start_collection()
