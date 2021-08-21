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

"""Verify the testbench generate 'connection reset' errors and continues working after them."""

import json
import re
import requests
import subprocess
import time
import unittest


class TestEmulatorContinueAfterFaultInjection(unittest.TestCase):
    def setUp(self):
        self.gunicorn = subprocess.Popen(
            [
                "gunicorn",
                "--bind=localhost:0",
                "--worker-class=sync",
                "--threads=2",
                "--reload",
                "--access-logfile=-",
                "emulator:run()",
            ],
            stderr=subprocess.PIPE,
            stdout=None,
            stdin=None,
            universal_newlines=True,
        )
        self.port = None
        start = time.time()
        # Wait for the message declaring this process is running
        while self.port is None and time.time() - start < 120:
            line = self.gunicorn.stderr.readline()
            if "Listening at: http://" in line:
                m = re.compile("Listening at:.*:([0-9]+) ").search(line)
                if m is not None:
                    self.port = m[1]
        self.assertIsNotNone(self.port)

    def tearDown(self):
        self.gunicorn.stderr.close()
        self.gunicorn.kill()
        self.gunicorn.wait(30)

    def test_repeated_reset_connection_faults(self):
        endpoint = "http://localhost:" + self.port

        # Setup the testbench to generate dozens of failures on bucket lists.
        faults = ["return-reset-connection"]
        faults = 100 * faults
        response = requests.post(
            endpoint + "/retry_test",
            data=json.dumps({"instructions": {"storage.buckets.list": faults}}),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.text)
        self.assertIn("id", create_rest)
        id = create_rest.get("id")

        # Verify we get the expected error when sending several requests
        for _ in range(0, 10):
            with self.assertRaises(requests.exceptions.RequestException) as ex:
                response = requests.get(
                    endpoint + "/storage/v1/b?project=test-project-unused",
                    headers={"x-retry-test-id": id},
                )

        # Verify the testbench remains usable.
        response = requests.get(endpoint + "/storage/v1/b?project=test-project-unused")
        self.assertEqual(response.status_code, 200)

    def test_repeated_broken_stream_faults(self):
        endpoint = "http://localhost:" + self.port

        # Setup the testbench to generate dozens of failures on bucket lists.
        faults = ["return-broken-stream"]
        faults = 100 * faults
        response = requests.post(
            endpoint + "/retry_test",
            data=json.dumps({"instructions": {"storage.buckets.list": faults}}),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.text)
        self.assertIn("id", create_rest)
        id = create_rest.get("id")

        # Verify we get the expected error when sending several requests
        for _ in range(0, 10):
            with self.assertRaises(requests.exceptions.RequestException) as ex:
                response = requests.get(
                    endpoint + "/storage/v1/b?project=test-project-unused",
                    headers={"x-retry-test-id": id},
                )

        # Verify the testbench remains usable.
        response = requests.get(endpoint + "/storage/v1/b?project=test-project-unused")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
