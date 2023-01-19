#!/usr/bin/env python3
#
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit test for testbench_waitress"""

import unittest


class TestTestbenchWaitress(unittest.TestCase):
    def test_created_wsgi_server_should_have_testbench_httpChannel(self):
        from testbench_waitress import testbench_create_server

        map = {}
        server_instance = testbench_create_server(
            application=object(),
            host="127.0.0.1",
            port=0,
            map=map,
            clear_untrusted_proxy_headers=False,
        )

        wsgi_server = None
        for key in map:
            if "WSGIServer" in map[key].__class__.__name__:
                wsgi_server = map[key]

        self.assertIsNotNone(wsgi_server)
        self.assertEqual(wsgi_server.channel_class.__name__, "testbench_HTTPChannel")
        self.assertEqual(
            wsgi_server.channel_class.task_class.__name__, "testbench_WSGITask"
        )

    def test_testbench_WSGITask_should_add_waitress_channel_in_environment_values(self):
        from testbench_waitress import testbench_WSGITask

        wsgiTaskInstance = testbench_WSGITask(object(), DummyRequest())
        wsgiTaskInstance.environ = {}
        environ = wsgiTaskInstance.get_environment()

        waitress_channel = environ.get("waitress.channel", None)

        self.assertIsNotNone(waitress_channel)


class DummyRequest:
    version = "1.0"


if __name__ == "__main__":
    unittest.main()
