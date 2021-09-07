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

"""Unit test for gcs.iam."""

import base64
import json
import unittest

from testbench.servers import iam_rest_server


class TestIam(unittest.TestCase):
    def setUp(self):
        _, app = iam_rest_server.get_iam_app()
        self.client = app.test_client()

    def test_sign_blob(self):
        response = self.client.post(
            "/projects/-/serviceAccounts/test-service-account:signBlob",
            data=json.dumps(
                {
                    "payload": base64.b64encode(
                        "please sign this".encode("utf-8")
                    ).decode("utf-8")
                }
            ),
        )
        response_data = json.loads(response.data)
        signed = base64.b64decode(response_data.get("signedBlob", None)).decode("utf-8")
        self.assertEqual("signed: please sign this", signed)

    def test_sign_blob_missing_payload(self):
        response = self.client.post(
            "/projects/-/serviceAccounts/test-service-account:signBlob",
            data=json.dumps({}),
        )
        self.assertEqual(response.status_code, 400)

    def test_sign_blob_payload_bad_format(self):
        response = self.client.post(
            "/projects/-/serviceAccounts/test-service-account:signBlob",
            data=json.dumps({"payload": "please sign this"}),
        )
        self.assertEqual(response.status_code, 400)
