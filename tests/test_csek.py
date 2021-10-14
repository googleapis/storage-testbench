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

"""Test for CSEK helpers."""

import base64
import hashlib
import unittest
from unittest.mock import ANY, Mock

import grpc
from werkzeug.test import create_environ
from werkzeug.wrappers import Request

from testbench import csek, error


class TestCSEK(unittest.TestCase):
    def test_extract_insert(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_type="application/json",
            method="POST",
            headers={
                "x-goog-encryption-algorithm": "AES",
                "x-goog-encryption-key": "test-only-invalid-key",
                "x-goog-encryption-key-sha256": "test-only-invalid-sha",
            },
        )
        algorithm, key, sha256 = csek.extract(Request(environ), False, None)
        self.assertEqual(algorithm, "AES")
        self.assertEqual(key, "test-only-invalid-key")
        self.assertEqual(sha256, "test-only-invalid-sha")

    def test_extract_copy(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_type="application/json",
            method="POST",
            headers={
                "x-goog-copy-source-encryption-algorithm": "AES",
                "x-goog-copy-source-encryption-key": "test-only-invalid-key",
                "x-goog-copy-source-encryption-key-sha256": "test-only-invalid-sha",
            },
        )
        algorithm, key, sha256 = csek.extract(Request(environ), True, None)
        self.assertEqual(algorithm, "AES")
        self.assertEqual(key, "test-only-invalid-key")
        self.assertEqual(sha256, "test-only-invalid-sha")

    def test_check_success(self):
        key = b"1234567890" + b"1234567890" + b"1234567890" + b"AA"
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        expected = hashlib.sha256(key).digest()
        actual = csek.check("AES256", key_b64, key_sha256, None)
        self.assertEqual(expected, actual)

    def test_check_invalid_algorithm(self):
        key = b"1234567890" + b"1234567890" + b"1234567890" + b"AA"
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        with self.assertRaises(error.RestException) as rest:
            _ = csek.check("#### INVALID ####", key_b64, key_sha256, None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        _ = csek.check("#### INVALID ####", key_b64, key_sha256, context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_check_invalid_key_length(self):
        key = b"## INVALID ##"
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        with self.assertRaises(error.RestException) as rest:
            _ = csek.check("AES256", key_b64, key_sha256, None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        _ = csek.check("AES256", key_b64, key_sha256, context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_check_invalid_hash(self):
        key = b"1234567890" + b"1234567890" + b"1234567890" + b"AA"
        key_sha256 = hashlib.sha256(b"## INVALID ##").digest()
        key_b64 = base64.b64encode(key)
        with self.assertRaises(error.RestException) as rest:
            _ = csek.check("AES256", key_b64, key_sha256, None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        _ = csek.check("AES256", key_b64, key_sha256, context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_validation_success(self):
        key = b"1234567890" + b"1234567890" + b"1234567890" + b"AA"
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        key_sha256_b64 = base64.b64encode(key_sha256).decode("utf-8")
        environ = create_environ(
            base_url="http://localhost:8080",
            content_type="application/json",
            method="POST",
            headers={
                "x-goog-encryption-algorithm": "AES256",
                "x-goog-encryption-key": key_b64,
                "x-goog-encryption-key-sha256": key_sha256_b64,
            },
        )
        csek.validation(Request(environ), key_sha256, False, None)

    def test_validation_failure(self):
        key = b"1234567890" + b"1234567890" + b"1234567890" + b"AA"
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        key_sha256_b64 = base64.b64encode(key_sha256).decode("utf-8")
        environ = create_environ(
            base_url="http://localhost:8080",
            content_type="application/json",
            method="POST",
            headers={
                "x-goog-encryption-algorithm": "## INVALID ##",
                "x-goog-encryption-key": key_b64,
                "x-goog-encryption-key-sha256": key_sha256_b64,
            },
        )
        with self.assertRaises(error.RestException) as rest:
            csek.validation(Request(environ), key_sha256, False, None)
        self.assertEqual(rest.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
