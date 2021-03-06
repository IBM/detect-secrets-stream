"""
 Copyright 2015-2018 IBM

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 Licensed Materials - Property of IBM
 © Copyright IBM Corp. 2015-2018
"""
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
