import pytest

from detect_secrets_stream.scan_worker.sanitizer import Sanitizer

# class SanitizerTest (TestCase):


@pytest.mark.parametrize(
    ('input', 'output'),
    [
        (
            '''{"results": {"filename": [{"type": "GitHub Enterprise Credentials"}]}}''',
            '''{"results": {"filename": [{"type": "GitHub Credentials"}]}}''',
        ),
        (
            '''{"results": {"filename": [{"type": "Other Credentials"}]}}''',
            '''{"results": {"filename": [{"type": "Other Credentials"}]}}''',
        ),
    ],
)
def test_convert_github_secret_type(input, output):
    assert Sanitizer.use_old_ghe_secret_type(input) == output
