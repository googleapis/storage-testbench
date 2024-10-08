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

"""Test for error handling helpers."""

import unittest
from unittest.mock import ANY, Mock

import grpc

from testbench import error


class TestError(unittest.TestCase):
    def test_csek(self):
        with self.assertRaises(error.RestException) as rest:
            error.csek(None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        error.csek(context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_invalid(self):
        with self.assertRaises(error.RestException) as rest:
            error.invalid("bad bucket name", None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        error.invalid("bad bucket name", context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_missing(self):
        with self.assertRaises(error.RestException) as rest:
            error.missing("object name", None)
        self.assertEqual(rest.exception.code, 400)

        context = Mock()
        error.missing("object name", context)
        context.abort.assert_called_once_with(grpc.StatusCode.INVALID_ARGUMENT, ANY)

    def test_mismatch(self):
        with self.assertRaises(error.RestException) as rest:
            error.mismatch("ifGenerationMatch", "0", "123", None)
        self.assertEqual(rest.exception.code, 412)

        context = Mock()
        error.mismatch("ifGenerationMatch", "0", "123", context)
        context.abort.assert_called_once_with(grpc.StatusCode.FAILED_PRECONDITION, ANY)

    def test_notchanged(self):
        with self.assertRaises(error.RestException) as rest:
            error.notchanged("ifGenerationNotMatch:7", None)
        self.assertEqual(rest.exception.code, 304)

        context = Mock()
        error.notchanged("ifGenerationNotMatch:7", context)
        context.abort.assert_called_once_with(grpc.StatusCode.ABORTED, ANY)

    def test_notfound(self):
        with self.assertRaises(error.RestException) as rest:
            error.notfound("test-object", None)
        self.assertEqual(rest.exception.code, 404)

        context = Mock()
        error.notfound("test-object", context)
        context.abort.assert_called_once_with(grpc.StatusCode.NOT_FOUND, ANY)

    def test_not_allowed(self):
        with self.assertRaises(error.RestException) as rest:
            error.notallowed(None)
        self.assertEqual(rest.exception.code, 405)

    def test_unimplemented(self):
        with self.assertRaises(error.RestException) as rest:
            error.unimplemented("requested method", None)
        self.assertEqual(rest.exception.code, 501)

        context = Mock()
        error.unimplemented("requested method", context)
        context.abort.assert_called_once_with(grpc.StatusCode.UNIMPLEMENTED, ANY)

    def test_inject_error(self):
        with self.assertRaises(error.RestException) as rest:
            error.inject_error(
                None, rest_code=503, grpc_code=grpc.StatusCode.UNAVAILABLE
            )
        self.assertEqual(rest.exception.code, 503)

        context = Mock()
        error.inject_error(
            context, rest_code=503, grpc_code=grpc.StatusCode.UNAVAILABLE
        )
        context.abort.assert_called_once_with(grpc.StatusCode.UNAVAILABLE, ANY)

    def test_not_soft_deleted_error(self):
        with self.assertRaises(error.RestException) as rest:
            error.not_soft_deleted(None)
        self.assertEqual(rest.exception.code, 412)

        context = Mock()
        error.not_soft_deleted(context)
        context.abort.assert_called_once_with(grpc.StatusCode.FAILED_PRECONDITION, ANY)


if __name__ == "__main__":
    unittest.main()
