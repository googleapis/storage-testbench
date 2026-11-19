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

"""Unit test for the root paths in the testbench."""

import os
import unittest
from unittest import mock

from testbench import rest_server


class TestTestbenchRoot(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        self.client = rest_server.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_root(self):
        response = self.client.get("/")
        self.assertEqual(response.data, b"OK")

    def test_raise_default(self):
        response = self.client.get("/raise_error", query_string={"msg": "test-only"})
        self.assertNotEqual(response.status_code, 200)
        self.assertIn("test-only", response.data.decode("utf-8"))

    def test_raise_type_error(self):
        response = self.client.get(
            "/raise_error", query_string={"etype": "type", "msg": "test-only"}
        )
        self.assertNotEqual(response.status_code, 200)
        self.assertIn("test-only", response.data.decode("utf-8"))

    def test_start_grpc_rejects_invalid_idle_timeout(self):
        for bad in ("0", "-1", "inf", "-inf", "nan", "not-a-number"):
            with self.subTest(bad=bad):
                response = self.client.get(
                    "/start_grpc",
                    query_string={"bidi-read-idle-timeout": bad},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(rest_server.grpc_port, 0)

    def test_start_grpc_uses_configured_host(self):
        cases = [
            (None, "localhost"),
            ("", "localhost"),
            ("127.0.0.1", "127.0.0.1"),
            ("0.0.0.0", "0.0.0.0"),
        ]
        for env_host, expected_host in cases:
            with self.subTest(env_host=env_host):
                env_patch = (
                    {} if env_host is None else {"STORAGE_TESTBENCH_HOST": env_host}
                )
                with mock.patch.dict(
                    os.environ, env_patch, clear=False
                ), mock.patch.object(
                    rest_server.testbench.grpc_server,
                    "run",
                    return_value=(12345, mock.MagicMock()),
                ) as mock_run:
                    if env_host is None:
                        os.environ.pop("STORAGE_TESTBENCH_HOST", None)
                    rest_server.grpc_port = 0
                    rest_server.grpc_service = None
                    try:
                        response = self.client.get("/start_grpc")
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.data, b"12345")
                        mock_run.assert_called_once()
                        self.assertEqual(
                            mock_run.call_args.kwargs["host"], expected_host
                        )
                    finally:
                        rest_server.grpc_port = 0
                        rest_server.grpc_service = None


if __name__ == "__main__":
    unittest.main()
