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
import json


class Sanitizer(object):

    @staticmethod
    def use_old_ghe_secret_type(input: str) -> str:
        '''
        Sanitize the output from detect secrets dev tool
        to use old (prior to 0.13.1+ibm.47.dss) secret type for GHE detector
        '''
        # sanitize raw secret before printing to logs
        results_dict = json.loads(input)
        for filename in results_dict['results']:
            for secret in results_dict['results'][filename]:
                # transform new GHE token type string from 'GitHub Enterprise Credentials'
                # to old value 'GitHub Credentials'
                if secret['type'] == 'GitHub Enterprise Credentials':
                    secret['type'] = 'GitHub Credentials'
        return json.dumps(results_dict)
