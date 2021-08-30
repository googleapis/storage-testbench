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

import re
import requests
import subprocess
import time
import unittest


class TestTestbenchStartup(unittest.TestCase):
    def setUp(self):
        self.gunicorn = subprocess.Popen(
            [
                "gunicorn",
                "--bind=localhost:0",
                "--worker-class=sync",
                "--threads=2",
                "--reload",
                "--access-logfile=-",
                "testbench:run()",
            ],
            stderr=subprocess.PIPE,
            stdout=None,
            stdin=None,
            universal_newlines=True,
        )
        self.plain = subprocess.Popen(
            [
                "python3",
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
        processes = [self.gunicorn, self.plain]
        for p in processes:
            p.stderr.close()
            p.kill()
            p.wait(30)

    def test_startup_gunicorn(self):
        started = False
        port = None
        start = time.time()
        # Wait for the message declaring this process is running
        while not started and time.time() - start < 120:
            line = self.gunicorn.stderr.readline()
            if "Listening at: http://" in line:
                m = re.compile("Listening at:.*:([0-9]+) ").search(line)
                if m is not None:
                    started = True
                    port = m[1]
        self.assertTrue(started)
        self.assertIsNotNone(port)
        response = requests.get("http://localhost:" + port)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")

    def test_startup_plain(self):
        started = False
        port = None
        start = time.time()
        # Wait for the message declaring this process is running
        while not started and time.time() - start < 120:
            line = self.plain.stderr.readline()
            if "Running on " in line:
                m = re.compile("Running on .*:([0-9]+)/ ").search(line)
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
