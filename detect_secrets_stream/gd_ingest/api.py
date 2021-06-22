#!/usr/bin/python
import json
import logging
import os
import signal
import sys
from functools import wraps

from flask import Flask
from flask import jsonify
from flask import request

from ..util.conf import ConfUtil
from ..util.log_util import LogUtil
from .gd_ingest import GDIngest


def load_basic_auth(basic_auth_pairs_str: str):
    if type(basic_auth_pairs_str) is not str:
        return {}

    return {
        basic_user: basic_pass
        for pair in basic_auth_pairs_str.split(',') if ':' in pair
        for basic_user, basic_pass in [pair.split(':', 1)]
    }


try:
    LogUtil.set_root_logger_json()
    logger = logging.getLogger(__name__)

    if os.getenv('DEBUG', False):  # pragma: no cover
        logger.info('Enabling debug...')
        logger.setLevel(logging.DEBUG)

    gd_kafka_conf = ConfUtil.load_kafka_conf()
    kafka_config = {
        'client.id': os.environ['KAFKA_CLIENT_ID'],
        'bootstrap.servers': gd_kafka_conf['brokers_sasl'],
        'security.protocol': 'SASL_SSL',
        'sasl.mechanisms': 'PLAIN',
        'sasl.username': 'token',
        'sasl.password': gd_kafka_conf['api_key'],
        'api.version.request': True,
        'broker.version.fallback': '0.10.2.1',
        'log.connection.close': False,
    }

    logger.info('Kafka Endpoints: %s' % (gd_kafka_conf['brokers_sasl']))

    basic_auth_conf = ConfUtil.load_basic_auth_conf()
    basic_auth_dict = load_basic_auth(basic_auth_conf['ingest'])

    # Create a gd_ingest object
    gd_ingest = GDIngest(kafka_config)

    tracer = gd_ingest.init_tracer()

    # Create a flask app
    app = Flask(__name__)

except Exception:
    logger.error('Exception while initializing app.', exc_info=1)
    sys.exit(1)


def sig_term_handler(signum, frame):  # pragma: no cover
    logger.info(
        'Signal SIGTERM has been received, no further requests will be processed, flask will exit within 30 seconds.',
    )


def check_auth(username, password):
    """
    check if a username/password combination is valid.
    """
    if not username or not password:
        return False

    return basic_auth_dict.get(username) == password


def requires_auth_response():
    """Sends a 401 response that enables basic auth"""
    resp = jsonify(
        {
            'success': False,
            'msg': 'Could not verify your access level for that URL. You have to login with proper credentials',
        },
    )
    resp.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
    resp.status_code = 401
    return resp


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return requires_auth_response()
        return f(*args, **kwargs)
    return decorated


def is_payload_valid(json_payload):
    must_have_fields = (
        'GITHUB_USER_LOGIN',
        'GITHUB_REPO_NAME',
        'GITHUB_REPO_PUBLIC',
        'stdin',
    )
    for field in must_have_fields:
        if json_payload.get(field) is None:
            return False
    return True


@app.route('/healthz', methods=['GET'])
def healthz():
    return 'Service operational', 200


@app.route('/api/v1/webhook/pre-receive', methods=['POST'])
@requires_auth
def pre_receive_webhook_v1():
    try:
        logger.info(
            'In pre_receive_webhook_v1.  Request JSON: %s.  Remote address: %s' % (
                request.json, request.remote_addr,
            ),
        )

        req_json = request.json
        if not is_payload_valid(req_json):
            raise Exception('Invalid payload')

        repo_slug = req_json.get('GITHUB_REPO_NAME')
        repo_public = req_json.get('GITHUB_REPO_PUBLIC')
        if repo_public != 'true' and repo_public != 'false':
            logger.info(
                'Received a unknown repo type %s for %s, ignoring...' % (
                    repo_public, repo_slug,
                ),
            )
        else:
            logger.info(
                'Received a public/private repo %s, adding to the scan queue...' % (
                    repo_slug
                ),
            )
            github_user = req_json.get('GITHUB_USER_LOGIN')
            json_payload = {
                'repoSlug': repo_slug,
                'githubUser': github_user,
                'repoPublic': repo_public,
            }
            for branch in req_json.get('stdin'):
                json_payload['branchName'] = ref_name = branch.get('ref_name')
                old_commit = branch.get('old_value')
                new_commit = branch.get('new_value')

                # ignore branch deletion
                if new_commit == '0000000000000000000000000000000000000000':
                    continue

                # ignore tags
                if ref_name and ref_name.startswith('refs/tags/'):
                    continue

                json_payload['oldCommit'] = old_commit
                json_payload['newCommit'] = new_commit

                gd_ingest.add_message_to_queue(
                    topic_name='diff-scan', message=json.dumps(json_payload),
                )
        return jsonify({'success': True}), 200
    except Exception:
        logger.error(
            'Exception while processing the pre-receive webhook.', exc_info=1,
        )
        return jsonify({'success': False}), 500


# Start the api server and set a signal handler to gracefully handle pod terminations
if __name__ == '__main__':  # pragma: no cover
    logger.info('Starting app...')
    signal.signal(signal.SIGTERM, sig_term_handler)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
