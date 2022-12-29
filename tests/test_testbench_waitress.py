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
import waitress
from testbench_waitress import testbench_WSGITask, testbench_HTTPChannel, testbench_create_server

dummy_app = object()

class TestTestbenchWaitress(unittest.TestCase):

    def _makeOne(
        self,
        application=dummy_app,
        host="127.0.0.1",
        port=0,
        _dispatcher=None,
        adj=None,
        map=None,
        _start=True,
        _sock=None,
        _server=None,
    ):
        from waitress.server import create_server

        sock = DummySock()
        task_dispatcher = DummyTaskDispatcher()
        map = {}

        self.inst = testbench_create_server(
            application=application,
            host=host,
            port=port,
            map=map,
            _dispatcher=task_dispatcher,
            _start=_start,
            _sock=sock,
        )
        return self.inst


    def test_serve(self):
        inst = self._makeOne(self ,_start=True)
        self.assertEqual(inst.accepting, True)
        self.assertEqual(inst.socket.listened, 1024)


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