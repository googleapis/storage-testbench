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

"""Unit test for utils"""

import base64
import gzip
import hashlib
import json
import types
import unittest
import unittest.mock

import flask
import grpc
from werkzeug.test import create_environ
from werkzeug.wrappers import Request
from google.storage.v2 import storage_pb2

import testbench_waitress


class TestTestbenchWaitress(unittest.TestCase):
    def test_testbench_HTTPChannel_should_have_testbench_WSGITask_task_class(self):

        mock_sock = unittest.mock.Mock()
        mock_sock.getsockopt = unittest.mock.Mock(return_value=None)

        mock_adj= unittest.mock.Mock()
        mock_adj.outbuf_overflow= unittest.mock.Mock(return_value=1)

        testbenchHTTPChannel = testbench_waitress.testbench_HTTPChannel(None, mock_sock, None, mock_adj)
        self.assertIsInstance(
            testbenchHTTPChannel.task_class,
            testbench_waitress.testbench_WSGITask,
            "testbench_HTTPChannel does not have testbench_WSGITask task_class",
        )
