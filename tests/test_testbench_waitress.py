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
import socket
from testbench_waitress import testbench_create_server

dummy_app=object()

class TestTestbenchWaitress(unittest.TestCase):

    def test_serve(self):
        server_instance = testbench_create_server(
            application=dummy_app,
            host="127.0.0.1",
            port=0,
            map= {},
            _dispatcher=DummyTaskDispatcher(),
            _start=True,
            _sock=DummySock(),
            clear_untrusted_proxy_headers=False,
        )

        print(server_instance.__class__.__name__)
        self.assertEqual(server_instance.accepting, True)
        self.assertEqual(server_instance.socket.listened, 1024)

    def test_serve_multi(self):
        server_instance = testbench_create_server(
            application=dummy_app,
            listen="127.0.0.1:0 127.0.0.1:0",
            map= {},
            _dispatcher=DummyTaskDispatcher(),
            _start=True,
            _sock=DummySock(),
            clear_untrusted_proxy_headers=False,
        )
        self.assertEqual(server_instance.__class__.__name__, "MultiSocketServer")

class DummyTaskDispatcher:
    def __init__(self):
        self.tasks = []

    def add_task(self, task):
        self.tasks.append(task)

    def shutdown(self):
        self.was_shutdown = True

class DummySock(socket.socket):
    accepted = False
    blocking = False
    family = socket.AF_INET
    type = socket.SOCK_STREAM
    proto = 0

    def __init__(self, toraise=None, acceptresult=(None, None)):
        self.toraise = toraise
        self.acceptresult = acceptresult
        self.bound = None
        self.opts = []
        self.bind_called = False

    def bind(self, addr):
        self.bind_called = True
        self.bound = addr

    def accept(self):
        if self.toraise:
            raise self.toraise
        self.accepted = True
        return self.acceptresult

    def setblocking(self, x):
        self.blocking = True

    def fileno(self):
        return 10

    def getpeername(self):
        return "127.0.0.1"

    def setsockopt(self, *arg):
        self.opts.append(arg)

    def getsockopt(self, *arg):
        return 1

    def listen(self, num):
        self.listened = num

    def getsockname(self):
        return self.bound

    def close(self):
        pass

if __name__ == "__main__":
    unittest.main()