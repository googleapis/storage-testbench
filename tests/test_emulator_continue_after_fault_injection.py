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

from requests.models import iter_slices


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

    @staticmethod
    def _create_block(desired_kib):
        line = "A" * 127 + "\n"
        return 1024 * int(desired_kib / len(line)) * line

    def test_repeated_broken_stream_faults_by_header(self):
        endpoint = "http://localhost:" + self.port

        # Create an object and bucket in the testbench.
        response = requests.post(
            endpoint + "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)
        # Use the XML API to inject an object with some data.
        media = self._create_block(2 * 1024)
        response = requests.put(
            endpoint + "/bucket-name/2MiB.txt",
            headers={"content-type": "text/plain"},
            data=media,
        )
        self.assertEqual(response.status_code, 200)

        # Verify we get the expected error (in this case the connection is closed) when sending several requests
        for _ in range(0, 4):
            with self.assertRaises(requests.exceptions.RequestException) as ex:
                response = requests.get(
                    endpoint + "/storage/v1/b/bucket-name/o/2MiB.txt?alt=media",
                    stream=True,
                    headers={"x-goog-testbench-instructions": "return-broken-stream"},
                )
                self.assertLess(
                    len(response.content), int(response.headers.get("content-length"))
                )
                self.assertNotEqual(response.status_code, 200)

        # Verify the testbench remains usable.
        response = requests.get(
            endpoint + "/storage/v1/b/bucket-name/o/2MiB.txt?alt=media"
        )
        self.assertEqual(response.status_code, 200)

    def test_repeated_error_after_256K_faults_by_header(self):
        endpoint = "http://localhost:" + self.port

        # Create an object and bucket in the testbench.
        response = requests.post(
            endpoint + "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)
        # Use the XML API to inject an object with some data.
        media = self._create_block(2 * 1024)
        response = requests.put(
            endpoint + "/bucket-name/2MiB.txt",
            headers={"content-type": "text/plain"},
            data=media,
        )
        self.assertEqual(response.status_code, 200)

        # Verify we get the expected error when sending several requests
        for _ in range(0, 10):
            with self.assertRaises(requests.exceptions.RequestException) as ex:
                response = requests.get(
                    endpoint + "/storage/v1/b/bucket-name/o/2MiB.txt?alt=media",
                    stream=True,
                    headers={"x-goog-testbench-instructions": "return-503-after-256K"},
                )
                _ = len(response.content)

        # Verify the testbench remains usable.
        response = requests.get(
            endpoint + "/storage/v1/b/bucket-name/o/2MiB.txt?alt=media"
        )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
