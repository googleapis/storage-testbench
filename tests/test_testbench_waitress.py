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

import sys

sys.path.append("C:\\Users\\anuraags\\gcp\\storage-testbench")

import unittest
import unittest.mock
from testbench_waitress import testbench_WSGITask, testbench_HTTPChannel


class TestTestbenchWaitress(unittest.TestCase):
    def test_get_environment_values(self):

        inst = testbench_WSGITask(DummyChannel(), DummyRequest())
        request = DummyRequest()
        # request.headers = {
        #     "CONTENT_TYPE": "abc",
        #     "CONTENT_LENGTH": "10",
        #     "X_FOO": "BAR",
        #     "CONNECTION": "close",
        # }
        # request.query = "abc"
        inst.request = request
        environ = inst.get_environment()

        channel = environ["waitress.channel"]

        self.assertIsNotNone(self, channel, "test message")
        # self.assertEquals(self, channel.__class__.__name__, "DummyChannel" ,)


class DummyRequest:

    version = "1.0"
    command = "GET"
    path = "/"
    request_uri = "/"
    query = ""
    url_scheme = "http"
    expect_continue = False
    headers_finished = False

    def __init__(self):
        self.headers = {}

    def get_body_stream(self):
        return "stream"


class DummyAdj:
    log_socket_errors = True
    ident = "waitress"
    host = "127.0.0.1"
    port = 80
    url_prefix = ""


class DummyServer:
    server_name = "localhost"
    effective_port = 80

    def __init__(self):
        self.adj = DummyAdj()


class DummyChannel:
    closed_when_done = False
    adj = DummyAdj()
    creation_time = 0
    addr = ("127.0.0.1", 39830)

    def check_client_disconnected(self):
        # For now, until we have tests handling this feature
        return False

    def __init__(self, server=None):
        if server is None:
            server = DummyServer()
        self.server = server
        self.written = b""
        self.otherdata = []

    def write_soon(self, data):
        if isinstance(data, bytes):
            self.written += data
        else:
            self.otherdata.append(data)
        return len(data)
