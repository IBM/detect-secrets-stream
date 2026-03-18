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
import asyncio
import logging
import os
import signal
import sys

from ..util.conf import ConfUtil
from ..util.log_util import LogUtil
from .diffscanworker import DiffScanWorker


class EventStreamsApp(object):

    def __init__(
        self,
        diff_scan_topic='diff-scan',
        notification_topic='notification',
        async_sleep_time=2,
    ):
        self.diff_scan_topic = diff_scan_topic
        self.notification_topic = notification_topic
        self.run_diff_scan_worker = True
        self.diff_scan_worker = None
        gd_kafka_config = ConfUtil.load_kafka_conf()
        self.kafka_config = {
            'client.id': os.environ['KAFKA_CLIENT_ID'],
            'group.id': os.environ['KAFKA_GROUP_ID'],
            'bootstrap.servers': gd_kafka_config['brokers_sasl'],
            'security.protocol': 'SASL_SSL',
            'sasl.mechanisms': 'PLAIN',
            'sasl.username': 'token',
            'sasl.password': gd_kafka_config['api_key'],
            'api.version.request': True,
            'broker.version.fallback': '0.10.2.1',
            'log.connection.close': False,
            # The time allowing consumer to use before it proactively leave group
            # See configuration doc in https://kafka.apache.org/documentation/#consumerconfigs
            'max.poll.interval.ms': int(
                os.getenv(
                    'KAFKA_MAX_POLL_INT_MS',
                    45      # Minutes
                    * 60    # Seconds
                    * 1000,  # Millisecond
                ),
            ),
            'session.timeout.ms': int(
                os.getenv(
                    'KAFKA_SESSION_TIMEOUT_MS',
                    5  # Minutes
                    * 60  # Seconds
                    * 1000,  # Millisecond
                ),
            ),
        }
        self.async_sleep_time = async_sleep_time
        self.logger = logging.getLogger(__name__)

    def shutdown(self, signal, frame):
        self.logger.info('Shutdown received.')
        if self.run_diff_scan_worker:
            self.diff_scan_worker.stop()

    @asyncio.coroutine
    def run_tasks(self):
        tasks = []
        if self.run_diff_scan_worker:
            self.diff_scan_worker = DiffScanWorker(
                self.kafka_config,
                self.diff_scan_topic,
                self.notification_topic,
                async_sleep_time=self.async_sleep_time,
            )
            tasks.append(asyncio.ensure_future(self.diff_scan_worker.run()))

        done, pending = yield from asyncio.wait(tasks)
        for future in done | pending:
            future.result()
        sys.exit(0)


if __name__ == '__main__':
    LogUtil.set_root_logger_json()

    app = EventStreamsApp()
    signal.signal(signal.SIGINT, app.shutdown)
    signal.signal(signal.SIGTERM, app.shutdown)
    print('This app will run until interrupted.')
    sys.exit(asyncio.get_event_loop().run_until_complete(app.run_tasks()))
