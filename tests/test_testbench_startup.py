#!/usr/bin/env python3
#
# Copyright 2021 Google LLC
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

"""Verify the testbench module starts a usable service."""

import json
import platform
import re
import subprocess
import time
import unittest

import grpc
import requests

from google.storage.v2 import storage_pb2, storage_pb2_grpc


class TestTestbenchStartup(unittest.TestCase):
    def python_command(self):
        if platform.system().lower() == "windows":
            return "py"
        return "python3"

    def setUp(self):
        self.testbench_server = subprocess.Popen(
            [self.python_command(), "testbench_run.py", "localhost", "0", "10"],
            stderr=subprocess.PIPE,
            stdout=None,
            stdin=None,
            universal_newlines=True,
        )
        self.plain = subprocess.Popen(
            [
                self.python_command(),
                "-m",
                "testbench",
                "--port=0",
            ],
            stderr=subprocess.PIPE,
            stdout=None,
            stdin=None,
            universal_newlines=True,
        )

    def tearDown(self):
        processes = [self.testbench_server, self.plain]
        for p in processes:
            p.stderr.close()
            p.kill()
            p.wait(30)

    def wait_testbench_server(self):
        started = False
        port = None
        start = time.time()

        # Declare default server start message and regex pattern for gunicorn
        server_start_message = "Listening at: http://"
        server_regex_pattern = "Listening at:.*:([0-9]+) "
        # If the tests are running on windows, change server start message and regex pattern for waitress
        if platform.system().lower() == "windows":
            server_start_message = "INFO:waitress:Serving on http://"
            server_regex_pattern = "INFO:waitress:Serving on.*:([0-9]+)"

        # Wait for the message declaring this process is running
        while not started and time.time() - start < 120:
            line = self.testbench_server.stderr.readline()
            if server_start_message in line:
                m = re.compile(server_regex_pattern).search(line)
                if m is not None:
                    started = True
                    port = m[1]
        self.assertTrue(started)
        return port

    def test_startup_server(self):
        port = self.wait_testbench_server()
        self.assertIsNotNone(port)
        response = requests.get("http://localhost:" + port)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")

    def test_startup_server_grpc(self):
        port = self.wait_testbench_server()
        self.assertIsNotNone(port)
        response = requests.post(
            "http://localhost:%s/storage/v1/b?project=test-only" % port,
            data=json.dumps({"name": "bucket-name"}),
        )
        self.assertEqual(response.status_code, 200, msg=response.text)
        response = requests.get("http://localhost:%s/start_grpc" % port)
        self.assertEqual(response.status_code, 200, msg=response.text)
        grpc_port = int(response.text)
        stub = storage_pb2_grpc.StorageStub(
            grpc.insecure_channel("localhost:%d" % grpc_port)
        )
        start = stub.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
        )
        self.assertIsNotNone(start.upload_id)
        self.assertNotEqual(start.upload_id, "")

    def test_startup_plain(self):
        started = False
        port = None
        start = time.time()
        # Wait for the message declaring this process is running
        while not started and time.time() - start < 120:
            line = self.plain.stderr.readline()
            if "Running on " in line:
                m = re.compile("Running on .*:([0-9]+)").search(line)
                if m is not None:
                    started = True
                    port = m[1]
        self.assertTrue(started)
        self.assertIsNotNone(port)
        response = requests.get("http://localhost:" + port)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")


if __name__ == "__main__":
    unittest.main()
