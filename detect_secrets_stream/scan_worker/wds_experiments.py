import json
import logging
import subprocess

from ..scan_worker.sanitizer import Sanitizer


class WDSExperiments(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def output_string(self, string):
        """ Print string to logs. """
        self.logger.info(string)

    def run_detect_secrets(self, filename):
        command = (
            'detect-secrets scan --no-keyword-scan --no-private-key-scan --no-basic-auth-scan '
            '--no-twilio-key-scan --no-base64-string-scan --no-hex-string-scan '
            '--no-jwt-scan --output-verified-false --output-raw %s' % filename
        )
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        results = output.decode('utf-8')
        results = Sanitizer.use_old_ghe_secret_type(results)
        return results

    def print_results(self, scan_results, secret_type, repo_slug, commit_hash):
        fp_count = 0
        tp_count = 0
        results_dict = json.loads(scan_results)
        for filename in results_dict['results']:
            for secret in results_dict['results'][filename]:
                if secret['type'] != secret_type:
                    continue

                if not secret['is_verified']:  # ignore entries which are not verified
                    continue

                if secret['verified_result']:
                    tp_count += 1
                else:
                    fp_count += 1
        self.output_string(
            json.dumps(
                {
                    'repo_slug': repo_slug,
                    'commit_hash': commit_hash,
                    'secret_type': secret_type,
                    'false_positives': fp_count,
                    'true_positives': tp_count,
                },
            ),
        )

    def evaluate_detector(self, filename, secret_type, repo_slug, commit_hash):
        """
        Runs detect-secrets scan on the file. Prints the false positives
        and true positives for one secret type.
        """

        results = self.run_detect_secrets(filename)
        self.print_results(results, secret_type, repo_slug, commit_hash)

    def compare_detectors(self, filename, secret_type_1, secret_type_2, repo_slug, commit_hash):
        """
        Runs detect-secrets scan on the file. Prints the false positives
        and true positives for each secret type.
        """

        results = self.run_detect_secrets(filename)
        self.print_results(results, secret_type_1, repo_slug, commit_hash)
        self.print_results(results, secret_type_2, repo_slug, commit_hash)
