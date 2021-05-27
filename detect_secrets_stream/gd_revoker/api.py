import logging
import signal
import sys
from functools import wraps

from flask import Flask
from flask import jsonify
from flask import request

from ..secret_corpus_db.db_biz import DbBiz
from ..util.conf import ConfUtil
from ..util.log_util import LogUtil


def load_basic_auth(basic_auth_pairs_str: str):
    if type(basic_auth_pairs_str) is not str:
        return {}

    return {
        basic_user: basic_pass
        for pair in basic_auth_pairs_str.split(',') if ':' in pair
        for basic_user, basic_pass in [pair.split(':', 1)]
    }


github_host = ConfUtil.load_github_conf()['host']

ERROR_MESSAGE = (
    'Invalid API call. Check the documentation for correct API syntax: '
    'https://github.com/IBM/detect-secrets-stream'
    '/blob/master/detect_secrets_stream/gd_revoker/usage.md'
)


try:
    LogUtil.set_root_logger_json()
    logger = logging.getLogger(__name__)
    basic_auth_conf = ConfUtil.load_basic_auth_conf()
    basic_auth_dict = load_basic_auth(basic_auth_conf['revoker'])
    revoker_requires_auth = basic_auth_conf['revoker-requires-auth']
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
        if revoker_requires_auth == 'true' and (not auth or not check_auth(auth.username, auth.password)):
            return requires_auth_response()
        return f(*args, **kwargs)
    return decorated


@app.route('/healthz', methods=['GET'])
def healthz():
    return 'Service operational', 200


@app.errorhandler(404)
def page_not_found(e):
    return jsonify(
        {
            'error':
            ERROR_MESSAGE,
        },
    ), 404


@app.errorhandler(405)
def wrong_method(e):
    return jsonify(
        {
            'error':
            ERROR_MESSAGE,
        },
    ), 405


@app.route('/api/v1/token/<uuid>/verify', methods=['POST'])
@requires_auth
def verify_token(uuid):
    logger.info(f'Receive request to verify secret {uuid}')
    try:
        secret = DbBiz().get_secret_from_db_by_uuid(uuid)
        if secret:
            logger.info(f'Retrieved secret {uuid}')
            if not secret.secret:
                logger.info(f'Secret {uuid} is no longer valid because raw secret is cleaned up.')
                return jsonify({'is_live': False, 'message': 'Secret was remediated, raw secret was cleaned up.'}), 200

            valid = secret.verify()
            if valid:
                logger.info(f'Secret {uuid} is still valid.')
                return jsonify({'is_live': True, 'message': 'Secret is active'}), 200
            else:
                logger.info(f'Secret {uuid} is no longer valid.')
                return jsonify({'is_live': False, 'message': 'Secret is remediated'}), 200
        else:
            logger.info(f'Secret {uuid} is not found.')
            return jsonify({'is_live': None, 'message': 'Secret not found'}), 404
    except Exception:
        logger.error('Failed to verify token {uuid}', exc_info=1)
        return jsonify({'is_live': None, 'message': 'Failed to validate secret'}), 200


@app.route('/api/v1/token/<uuid>/revoke', methods=['POST'])
@requires_auth
def revoke_token(uuid):
    logger.info(f'Receive request to revoke secret {uuid}')
    try:
        secret = DbBiz().get_secret_from_db_by_uuid(uuid)
        if not secret:
            logger.info(f'Secret {uuid} is not found.')
            return jsonify({'success': False, 'message': 'Token with uuid %s was not found' % uuid}), 404

        try:
            logger.info(f'Retrieved secret {uuid}')
            if not secret.secret:
                logger.info(f'Secret {uuid} is no longer valid because raw secret is cleaned up.')
                return jsonify({
                    'success': True,
                    'message': 'Token with uuid %s is already inactive due to raw secret been cleaned up' % uuid,
                }), 200

            valid = secret.verify()
            if not valid:
                logger.info(f'Secret {uuid} is no longer valid.')
                return jsonify({'success': True, 'message': 'Token with uuid %s is already inactive' % uuid}), 200
        except Exception:
            logger.warning('Fail to verify secret from revocation API, attempting to revoke anyway', exc_info=1)

        revoke_result = secret.revoke()
        if revoke_result:
            logger.info(f'Secret {uuid} is successfully revoked.')
            return jsonify({'success': True, 'message': 'Token with uuid %s has been revoked' % uuid}), 200
        elif revoke_result is None:
            logger.info(f'Secret {uuid} is not revoked due to unsupported token type {secret.secret_type}.')
            return jsonify(
                {'success': False, 'message': 'Revocation not implemented for token type %s' % secret.secret_type},
            ), 200
        else:
            logger.info(f'Secret {uuid} is failed to be revoked.')
            return jsonify({'success': False, 'message': 'Failed to revoke token with uuid %s' % uuid}), 200
    except Exception as e:
        logger.error('Failed to revoke token {uuid} with exception', exc_info=1)
        return jsonify(
            {
                'success': False,
                'message': 'Failed to revoke token with uuid %s. Error: %s' % (uuid, str(e)),
            },
        ), 200


# Start the api server and set a signal handler to gracefully handle pod terminations
if __name__ == '__main__':  # pragma: no cover
    logger.info('Starting app...')
    signal.signal(signal.SIGTERM, sig_term_handler)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
