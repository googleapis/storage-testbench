#!/usr/bin/env python3
#
# Copyright 2020 Google LLC
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

"""Unit test for utils"""

import flask
import json
import unittest

from werkzeug.test import create_environ
from werkzeug.wrappers import Request
from google.cloud.storage_v1.proto import storage_pb2 as storage_pb2

import testbench


class TestCommonUtils(unittest.TestCase):
    def test_snake_case(self):
        self.assertEqual(
            testbench.common.to_snake_case("authenticatedRead"), "authenticated_read"
        )
        self.assertEqual(
            testbench.common.to_snake_case("allAuthenticatedUsers"),
            "all_authenticated_users",
        )

    def test_parse_fields(self):
        fields = "kind, items ( acl( entity, role), name, id)"
        self.assertCountEqual(
            testbench.common.parse_fields(fields),
            ["kind", "items.acl.entity", "items.acl.role", "items.name", "items.id"],
        )

        fields = "kind, items(name, labels(number), acl(role))"
        self.assertCountEqual(
            testbench.common.parse_fields(fields),
            ["kind", "items.name", "items.labels.number", "items.acl.role"],
        )

    def test_remove_index(self):
        key = "items[1].name[0].id[0].acl"
        self.assertEqual(testbench.common.remove_index(key), "items.name.id.acl")

    def test_fake_request_init_xml(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=0,
            data="",
            content_type="application/octet-stream",
            method="POST",
            headers={
                "x-goog-if-generation-match": 1234,
                "x-goog-if-metageneration-match": 2345,
                "x-goog-acl": "projectPrivate",
            },
        )
        request = testbench.common.FakeRequest.init_xml(Request(environ))
        subset = {
            "ifGenerationMatch": "1234",
            "ifMetagenerationMatch": "2345",
            "predefinedAcl": "projectPrivate",
        }
        self.assertEqual(request.args, {**request.args, **subset})

    def test_fake_request_init_protobuf(self):
        class MockContext(object):
            pass

        protobuf_request = storage_pb2.QueryWriteStatusRequest()
        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        print("\n\n%s\n\n" % request)

    def test_nested_key(self):
        doc = {
            "name": "bucket",
            "acl": [{"id": 1}, {"id": 2}],
            "labels": {"first": 1, "second": [1, 2]},
        }
        self.assertCountEqual(
            testbench.common.nested_key(doc),
            [
                "name",
                "acl[0].id",
                "acl[1].id",
                "labels.first",
                "labels.second[0]",
                "labels.second[1]",
            ],
        )

    def test_extract_projection(self):
        request = testbench.common.FakeRequest(args={})
        projection = testbench.common.extract_projection(request, "noAcl", None)
        self.assertEqual(projection, "noAcl")
        request.args["projection"] = "full"
        projection = testbench.common.extract_projection(request, "noAcl", None)
        self.assertEqual(projection, "full")

    def test_filter_response_rest(self):
        response = {
            "kind": "storage#buckets",
            "items": [
                {
                    "name": "bucket1",
                    "labels": {"number": "1", "order": "1"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
                {
                    "name": "bucket2",
                    "labels": {"number": "2", "order": "2"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
                {
                    "name": "bucket3",
                    "labels": {"number": "3", "order": "3"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
            ],
        }
        response_full = testbench.common.filter_response_rest(
            response, "full", "kind, items(name, labels(number), acl(role))"
        )
        self.assertDictEqual(
            response_full,
            {
                "kind": "storage#buckets",
                "items": [
                    {
                        "name": "bucket1",
                        "labels": {"number": "1"},
                        "acl": [{"role": "OWNER"}],
                    },
                    {
                        "name": "bucket2",
                        "labels": {"number": "2"},
                        "acl": [{"role": "OWNER"}],
                    },
                    {
                        "name": "bucket3",
                        "labels": {"number": "3"},
                        "acl": [{"role": "OWNER"}],
                    },
                ],
            },
        )

        response = {
            "kind": "storage#buckets",
            "items": [
                {
                    "name": "bucket1",
                    "labels": {"number": "1", "order": "1"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
                {
                    "name": "bucket2",
                    "labels": {"number": "2", "order": "2"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
                {
                    "name": "bucket3",
                    "labels": {"number": "3", "order": "3"},
                    "acl": [{"entity": "entity", "role": "OWNER"}],
                },
            ],
        }
        response_noacl = testbench.common.filter_response_rest(
            response, "noAcl", "items(name, labels)"
        )
        self.assertDictEqual(
            response_noacl,
            {
                "items": [
                    {"name": "bucket1", "labels": {"number": "1", "order": "1"}},
                    {"name": "bucket2", "labels": {"number": "2", "order": "2"}},
                    {"name": "bucket3", "labels": {"number": "3", "order": "3"}},
                ]
            },
        )

    def test_parse_multipart(self):
        request = testbench.common.FakeRequest(
            headers={"content-type": "multipart/related; boundary=foo_bar_baz"},
            data=b'--foo_bar_baz\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{"name": "myObject", "metadata": {"test": "test"}}\r\n--foo_bar_baz\r\nContent-Type: image/jpeg\r\n\r\n123456789\r\n--foo_bar_baz--\r\n',
            environ={},
        )
        metadata, media_header, media = testbench.common.parse_multipart(request)
        self.assertDictEqual(
            metadata, {"name": "myObject", "metadata": {"test": "test"}}
        )
        self.assertDictEqual(media_header, {"content-type": "image/jpeg"})
        self.assertEqual(media, b"123456789")

        # In some cases, data media contains "\r\n" which could confuse `parse_multipart`
        request = testbench.common.FakeRequest(
            headers={"content-type": "multipart/related; boundary=1VvZTD07ltUtqMHg"},
            data=b'--1VvZTD07ltUtqMHg\r\ncontent-type: application/json; charset=UTF-8\r\n\r\n{"crc32c":"4GEvYA=="}\r\n--1VvZTD07ltUtqMHg\r\ncontent-type: application/octet-stream\r\n\r\n\xa7#\x95\xec\xd5c\xe9\x90\xa8\xe2\xa89\xadF\xcc\x97\x12\xad\xf6\x9e\r\n\xf1Mhj\xf4W\x9f\x92T\xe3,\tm.\x1e\x04\xd0\r\n--1VvZTD07ltUtqMHg--\r\n',
            environ={},
        )
        metadata, media_header, media = testbench.common.parse_multipart(request)
        self.assertDictEqual(metadata, {"crc32c": "4GEvYA=="})
        self.assertDictEqual(media_header, {"content-type": "application/octet-stream"})
        self.assertEqual(
            media,
            b"\xa7#\x95\xec\xd5c\xe9\x90\xa8\xe2\xa89\xadF\xcc\x97\x12\xad\xf6\x9e\r\n\xf1Mhj\xf4W\x9f\x92T\xe3,\tm.\x1e\x04\xd0",
        )

        # Test line ending without "\r\n"
        request = testbench.common.FakeRequest(
            headers={"content-type": "multipart/related; boundary=1VvZTD07ltUtqMHg"},
            data=b'--1VvZTD07ltUtqMHg\r\ncontent-type: application/json; charset=UTF-8\r\n\r\n{"crc32c":"4GEvYA=="}\r\n--1VvZTD07ltUtqMHg\r\ncontent-type: application/octet-stream\r\n\r\n\xa7#\x95\xec\xd5c\xe9\x90\xa8\xe2\xa89\xadF\xcc\x97\x12\xad\xf6\x9e\r\n\xf1Mhj\xf4W\x9f\x92T\xe3,\tm.\x1e\x04\xd0\r\n--1VvZTD07ltUtqMHg--',
            environ={},
        )
        metadata, media_header, media = testbench.common.parse_multipart(request)
        self.assertDictEqual(metadata, {"crc32c": "4GEvYA=="})
        self.assertDictEqual(media_header, {"content-type": "application/octet-stream"})
        self.assertEqual(
            media,
            b"\xa7#\x95\xec\xd5c\xe9\x90\xa8\xe2\xa89\xadF\xcc\x97\x12\xad\xf6\x9e\r\n\xf1Mhj\xf4W\x9f\x92T\xe3,\tm.\x1e\x04\xd0",
        )

        # Test incorrect multipart body
        request = testbench.common.FakeRequest(
            headers={"content-type": "multipart/related; boundary=1VvZTD07ltUtqMHg"},
            data=b'--1VvZTD07ltUtqMHg\r\ncontent-type: application/json; charset=UTF-8\r\n{"crc32c":"4GEvYA=="}\r\n--1VvZTD07ltUtqMHg\r\ncontent-type: application/octet-stream\r\n\xa7#\x95\xec\xd5c\xe9\x90\xa8\xe2\xa89\xadF\xcc\x97\x12\xad\xf6\x9e\r\n\xf1Mhj\xf4W\x9f\x92T\xe3,\tm.\x1e\x04\xd0\r\n',
            environ={},
        )
        with self.assertRaises(testbench.error.RestException):
            testbench.common.parse_multipart(request)

    def test_corrupt_media(self):
        input = b"How vexingly quick daft zebras jump!"
        self.assertNotEqual(input, testbench.common.corrupt_media(input))

    def test_extract_instruction_grpc(self):
        class MockContext(object):
            pass

        context = MockContext()
        context.invocation_metadata = lambda: {
            "x-goog-emulator-instructions": "do-stuff"
        }.items()
        self.assertEqual(
            "do-stuff", testbench.common.extract_instruction(None, context)
        )

    def test_extract_instruction_rest(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=0,
            data="",
            content_type="application/octet-stream",
            method="POST",
            headers={"x-goog-testbench-instructions": "do-stuff"},
        )
        self.assertEqual(
            "do-stuff", testbench.common.extract_instruction(Request(environ), None)
        )

    def test_enforce_patch_override_failure(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=0,
            data="",
            content_type="application/octet-stream",
            method="POST",
            headers={"X-Http-Method-Override": "other"},
        )
        with self.assertRaises(testbench.error.RestException):
            testbench.common.enforce_patch_override(Request(environ))

    def test_enforce_patch_override_success(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=0,
            data="",
            content_type="application/octet-stream",
            method="POST",
            headers={"X-Http-Method-Override": "PATCH"},
        )
        testbench.common.enforce_patch_override(Request(environ))

    def test_crc32c_to_from_proto(self):
        # used an external tool to get the CRC32C of:
        #    /bin/echo -n 'The quick brown fox jumps over the lazy dog' > fox.txt
        #    gsutil hash foo.txt
        # it prints
        #    Hash (crc32c):		ImIEBA==
        # then use:
        #    echo ImIEBA== | openssl base64 -d | xxd -p
        # that prints
        #    22620404
        self.assertEqual(0x22620404, testbench.common.rest_crc32c_to_proto("ImIEBA=="))
        self.assertEqual(
            "ImIEBA==", testbench.common.rest_crc32c_from_proto(0x22620404)
        )

    def test_rfc3339_to_proto(self):
        # used external tool to get the date:
        #   /usr/bin/date --rfc-3339=ns -u --date=@1627688798.123456789
        actual = testbench.common.rest_rfc3339_to_proto(
            "2021-07-30T23:46:38.123456789Z"
        )
        self.assertEqual(actual.seconds, 1627688798)
        self.assertEqual(actual.nanos, 123456789)

    def test_rest_adjust(self):
        input = {
            "old-name": "old-value",
            "append-to-value": "prefix-",
            "removed": "unused",
            "untouched": "preserve-value",
        }
        actual = testbench.common.rest_adjust(
            input,
            {
                "old-name": lambda x: ("new-name", x),
                "append-to-value": lambda x: ("append-to-value", x + "suffix"),
                "removed": lambda x: (None, None),
            },
        )
        self.assertDictEqual(
            actual,
            {
                "new-name": "old-value",
                "append-to-value": "prefix-suffix",
                "untouched": "preserve-value",
            },
        )

    def test_extract_data(self):
        """Verify the helper function __extract_data() works with different input types."""
        fox = "The quick brown fox jumps over the lazy dog"
        actual = testbench.common._extract_data(fox)
        self.assertEqual(actual, fox)

        expected = json.dumps({"text": fox})
        actual = testbench.common._extract_data({"text": fox})
        self.assertEqual(actual, expected)

        actual = testbench.common._extract_data(flask.Response(fox))
        self.assertEqual(actual.decode("utf-8"), fox)


if __name__ == "__main__":
    unittest.main()
