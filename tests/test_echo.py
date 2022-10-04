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

"""Test the embedded echo server."""

import unittest
import json
import os
import unittest

from testbench import rest_server


class TestEcho(unittest.TestCase):
    def setUp(self):
        self.client = rest_server.server.wsgi_application.test_client()

    def test_delete(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        response = self.client.delete(
            "/httpbin/delete",
            query_string=expected_args,
            headers=expected_headers,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})

    def test_get(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        response = self.client.get(
            "/httpbin/get",
            query_string=expected_args,
            headers=expected_headers,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})

    def test_patch(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = "The quick brown fox jumps over the lazy dog"
        response = self.client.patch(
            "/httpbin/patch",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("data", ""), expected_data)

    def test_post(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = "The quick brown fox jumps over the lazy dog"
        response = self.client.post(
            "/httpbin/post",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("data", ""), expected_data)

    def test_post_form(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.post(
            "/httpbin/post",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)

    def test_put(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/httpbin/put",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("data", ""), expected_data)

    def test_status_code(self):
        for code in [308, 404, 418, 500, 503]:
            response = self.client.delete("/httpbin/status/%d" % code)
            self.assertEqual(response.status_code, code, msg=response.data)
            response = self.client.get("/httpbin/status/%d" % code)
            self.assertEqual(response.status_code, code, msg=response.data)
            response = self.client.patch("/httpbin/status/%d" % code)
            self.assertEqual(response.status_code, code, msg=response.data)
            response = self.client.post("/httpbin/status/%d" % code)
            self.assertEqual(response.status_code, code, msg=response.data)
            response = self.client.put("/httpbin/status/%d" % code)
            self.assertEqual(response.status_code, code, msg=response.data)

    def test_stream(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        response = self.client.get(
            "/httpbin/stream/8",
            query_string=expected_args,
            headers=expected_headers,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        lines = response.data.split(b"\n")
        self.assertEqual(len(lines), 9)  # Includes empty line
        for count, line in enumerate(lines):
            if len(line) == 0:
                continue
            payload = json.loads(line)
            self.assertEqual(payload.get("id"), count)
            self.assertEqual(payload.get("args", dict()), expected_args)
            actual_headers = {
                key.lower(): value
                for key, value in payload.get("headers", dict()).items()
            }
            self.assertEqual(actual_headers, {**actual_headers, **expected_headers})

    def test_headers(self):
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        response = self.client.get("/httpbin/headers", headers=expected_headers)
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})

    def test_reponse_headers(self):
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        response = self.client.get(
            "/httpbin/response-headers", query_string=expected_headers
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        actual_headers = {key.lower(): value for key, value in response.headers.items()}
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})

    def test_delete_anything(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.delete(
            "/httpbin/anything",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)

    def test_get_anything(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.get(
            "/httpbin/anything",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)

    def test_patch_anything(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.patch(
            "/httpbin/anything",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)

    def test_post_anything(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.post(
            "/httpbin/anything",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)

    def test_put_anything(self):
        expected_args = {"arg1": "value1", "arg2": "value2"}
        expected_headers = {
            "x-goog-test1": "test-header1",
            "x-goog-test2": "test-header2",
        }
        expected_data = {
            "form-key0": "value0",
            "form-key1": "value1 & value2 & value3=x",
        }
        response = self.client.put(
            "/httpbin/anything",
            query_string=expected_args,
            headers=expected_headers,
            data=expected_data,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json"),
            msg="content-type == %s" % response.headers.get("content-type", ""),
        )
        payload = json.loads(response.data)
        self.assertEqual(payload.get("args", dict()), expected_args)
        actual_headers = {
            key.lower(): value for key, value in payload.get("headers", dict()).items()
        }
        self.assertEqual(actual_headers, {**actual_headers, **expected_headers})
        self.assertEqual(payload.get("form", dict()), expected_data)


if __name__ == "__main__":
    unittest.main()
