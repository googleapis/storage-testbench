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

"""Unit tests for testbench.handle_gzip."""

import gzip
import unittest

from werkzeug.test import create_environ

import testbench


class TestHandleGzip(unittest.TestCase):
    def test_handle_decompressing(self):
        plain_text = b"hello world"
        compressed_text = gzip.compress(plain_text)
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(compressed_text),
            data=compressed_text,
            content_type="application/octet-stream",
            method="GET",
            headers={"Content-Encoding": "gzip"},
        )

        def passthrough_fn(environ, _):
            return environ

        middleware = testbench.handle_gzip.HandleGzipMiddleware(passthrough_fn)
        decompressed_environ = middleware(environ, None)
        self.assertEqual(decompressed_environ["werkzeug.request"].data, plain_text)


if __name__ == "__main__":
    unittest.main()
