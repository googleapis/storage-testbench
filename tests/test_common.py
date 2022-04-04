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

import base64
import hashlib
import json
import types
import unittest
import unittest.mock

import flask
import grpc
from werkzeug.test import create_environ
from werkzeug.wrappers import Request
from google.storage.v2 import storage_pb2

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
        self.assertTrue(hasattr(request, "environ"))
        self.assertIn("REQUEST_METHOD", request.environ)

    def test_fake_request_init_protobuf_start_resumable_write(self):
        class MockContext(object):
            pass

        key_bytes = b"\001\002\003\004\005\006\007\010"
        key_sh256_bytes = hashlib.sha256(key_bytes).digest()
        protobuf_request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
                predefined_acl="projectPrivate",
                if_generation_match=1,
                if_generation_not_match=2,
                if_metageneration_match=3,
                if_metageneration_not_match=4,
            ),
            common_object_request_params=storage_pb2.CommonObjectRequestParams(
                encryption_algorithm="RSA256",
                encryption_key_bytes=key_bytes,
                encryption_key_sha256_bytes=key_sh256_bytes,
            ),
            common_request_params=storage_pb2.CommonRequestParams(
                user_project="projects/123456",
            ),
        )

        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        expected_headers = {
            "x-goog-encryption-algorithm": "RSA256",
            "x-goog-encryption-key": base64.b64encode(key_bytes).decode("utf-8"),
            "x-goog-encryption-key-sha256": base64.b64encode(key_sh256_bytes).decode(
                "utf-8"
            ),
        }
        self.assertEqual(request.headers, {**request.headers, **expected_headers})
        self.assertEqual(request.args, {"userProject": "123456"})

        request.update_protobuf(protobuf_request.write_object_spec, MockContext())
        expected_args = {
            "ifGenerationMatch": 1,
            "ifGenerationNotMatch": 2,
            "ifMetagenerationMatch": 3,
            "ifMetagenerationNotMatch": 4,
            "predefinedAcl": "projectPrivate",
        }
        self.assertEqual(request.args, {**request.args, **expected_args})

    def test_fake_request_init_protobuf_write_object(self):
        class MockContext(object):
            pass

        key_bytes = b"\001\002\003\004\005\006\007\010"
        key_sh256_bytes = hashlib.sha256(key_bytes).digest()
        protobuf_request = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
                predefined_acl="projectPrivate",
                if_generation_match=1,
                if_generation_not_match=2,
                if_metageneration_match=3,
                if_metageneration_not_match=4,
            ),
            common_object_request_params=storage_pb2.CommonObjectRequestParams(
                encryption_algorithm="RSA256",
                encryption_key_bytes=key_bytes,
                encryption_key_sha256_bytes=key_sh256_bytes,
            ),
            common_request_params=storage_pb2.CommonRequestParams(
                user_project="projects/123456",
            ),
        )

        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        expected_headers = {
            "x-goog-encryption-algorithm": "RSA256",
            "x-goog-encryption-key": base64.b64encode(key_bytes).decode("utf-8"),
            "x-goog-encryption-key-sha256": base64.b64encode(key_sh256_bytes).decode(
                "utf-8"
            ),
        }
        self.assertEqual(request.headers, {**request.headers, **expected_headers})
        self.assertEqual(request.args, {"userProject": "123456"})

        request.update_protobuf(protobuf_request.write_object_spec, MockContext())
        expected_args = {
            "ifGenerationMatch": 1,
            "ifGenerationNotMatch": 2,
            "ifMetagenerationMatch": 3,
            "ifMetagenerationNotMatch": 4,
            "predefinedAcl": "projectPrivate",
        }
        self.assertEqual(request.args, {**request.args, **expected_args})

    def test_fake_request_init_protobuf_read_object(self):
        class MockContext(object):
            pass

        key_bytes = b"\001\002\003\004\005\006\007\010"
        key_sh256_bytes = hashlib.sha256(key_bytes).digest()
        protobuf_request = storage_pb2.ReadObjectRequest(
            bucket="projects/_/buckets/bucket-name",
            object="object",
            generation=7,
            if_generation_match=1,
            if_generation_not_match=2,
            if_metageneration_match=3,
            if_metageneration_not_match=4,
            common_object_request_params=storage_pb2.CommonObjectRequestParams(
                encryption_algorithm="RSA256",
                encryption_key_bytes=key_bytes,
                encryption_key_sha256_bytes=key_sh256_bytes,
            ),
            common_request_params=storage_pb2.CommonRequestParams(
                user_project="projects/123456",
            ),
        )

        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        expected_headers = {
            "x-goog-encryption-algorithm": "RSA256",
            "x-goog-encryption-key": base64.b64encode(key_bytes).decode("utf-8"),
            "x-goog-encryption-key-sha256": base64.b64encode(key_sh256_bytes).decode(
                "utf-8"
            ),
        }
        self.assertEqual(request.headers, {**request.headers, **expected_headers})
        expected_args = {
            "ifGenerationMatch": 1,
            "ifGenerationNotMatch": 2,
            "ifMetagenerationMatch": 3,
            "ifMetagenerationNotMatch": 4,
            "userProject": "123456",
        }
        self.assertEqual(request.args, {**request.args, **expected_args})

    def test_fake_request_init_protobuf_read_object_simple(self):
        class MockContext(object):
            pass

        protobuf_request = storage_pb2.ReadObjectRequest(
            bucket="projects/_/buckets/bucket-name",
            object="object",
        )

        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        self.assertIsNone(request.if_generation_match)
        self.assertIsNone(request.if_generation_not_match)
        self.assertIsNone(request.if_metageneration_match)
        self.assertIsNone(request.if_metageneration_not_match)
        self.assertIsNone(request.predefined_acl)
        self.assertEqual(request.generation, 0)
        p = request.common_object_request_params
        self.assertEqual(p.encryption_algorithm, "")
        self.assertEqual(p.encryption_key_bytes, b"")
        self.assertEqual(p.encryption_key_sha256_bytes, b"")

    def test_fake_request_init_protobuf_write_object_simple(self):
        class MockContext(object):
            pass

        protobuf_request = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
        )

        request = testbench.common.FakeRequest.init_protobuf(
            protobuf_request, MockContext()
        )
        self.assertIsNone(request.if_generation_match)
        self.assertIsNone(request.if_generation_not_match)
        self.assertIsNone(request.if_metageneration_match)
        self.assertIsNone(request.if_metageneration_not_match)
        self.assertIsNone(request.predefined_acl)
        self.assertEqual(request.generation, 0)
        p = request.common_object_request_params
        self.assertEqual(p.encryption_algorithm, "")
        self.assertEqual(p.encryption_key_bytes, b"")
        self.assertEqual(p.encryption_key_sha256_bytes, b"")

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
                "acl[0]",
                "acl[1].id",
                "acl[1]",
                "acl",
                "labels.first",
                "labels.second[0]",
                "labels.second[1]",
                "labels.second",
                "labels",
            ],
        )

    def make_test_json_preconditions(self, query_string):
        """Helper function to test JSON preconditions."""
        return testbench.common.make_json_preconditions(
            Request(
                create_environ(
                    base_url="http://localhost:8080",
                    content_length=0,
                    data="",
                    content_type="application/octet-stream",
                    method="POST",
                    headers={},
                    query_string=query_string,
                )
            ),
        )

    def test_make_json_preconditions_empty(self):
        preconditions = self.make_test_json_preconditions({})
        self.assertEqual(len(preconditions), 0)

    def test_make_json_preconditions_many(self):
        preconditions = self.make_test_json_preconditions(
            {
                "ifGenerationMatch": "5",
                "ifGenerationNotMatch": "5",
                "ifMetagenerationMatch": "5",
                "ifMetagenerationNotMatch": "5",
            }
        )
        self.assertEqual(len(preconditions), 4)

    def test_make_json_preconditions_source(self):
        preconditions = testbench.common.make_json_preconditions(
            prefix="ifSource",
            request=Request(
                create_environ(
                    base_url="http://localhost:8080",
                    content_length=0,
                    data="",
                    content_type="application/octet-stream",
                    method="POST",
                    headers={},
                    query_string={
                        "ifSourceGenerationMatch": "5",
                        "ifSourceGenerationNotMatch": "5",
                        "ifSourceMetagenerationMatch": "5",
                        "ifSourceMetagenerationNotMatch": "5",
                    },
                )
            ),
        )
        self.assertEqual(len(preconditions), 4)

    def test_make_json_preconditions_if_generation_match(self):
        preconditions = self.make_test_json_preconditions({"ifGenerationMatch": "5"})
        self.assertEqual(len(preconditions), 1)
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))
        self.assertTrue(preconditions[0](blob, 5, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](blob, 6, None)
        self.assertEqual(rest.exception.code, 412)

        preconditions = self.make_test_json_preconditions({"ifGenerationMatch": "0"})
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, None, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](None, 6, None)
        self.assertEqual(rest.exception.code, 412)

    def test_make_json_preconditions_if_generation_not_match(self):
        preconditions = self.make_test_json_preconditions({"ifGenerationNotMatch": "5"})
        self.assertEqual(len(preconditions), 1)
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))
        self.assertTrue(preconditions[0](blob, 6, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](blob, 5, None)
        self.assertEqual(rest.exception.code, 304)

        preconditions = self.make_test_json_preconditions({"ifGenerationNotMatch": "0"})
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, 5, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](None, None, None)
        self.assertEqual(rest.exception.code, 304)

    def test_make_json_preconditions_if_metageneration_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6))

        preconditions = self.make_test_json_preconditions(
            {"ifMetagenerationMatch": "5"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b0, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, 3, None)
        self.assertEqual(rest.exception.code, 412)

        preconditions = self.make_test_json_preconditions(
            {"ifMetagenerationMatch": "0"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, 3, None)
        self.assertEqual(rest.exception.code, 412)

    def test_make_json_preconditions_if_metageneration_not_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6))

        preconditions = self.make_test_json_preconditions(
            {"ifMetagenerationNotMatch": "5"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b1, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b0, 3, None)
        self.assertEqual(rest.exception.code, 304)

        preconditions = self.make_test_json_preconditions(
            {"ifMetagenerationNotMatch": "0"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b0, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](None, 3, None)
        self.assertEqual(rest.exception.code, 304)

    def make_test_xml_preconditions(self, headers):
        """Helper function to test XML preconditions."""
        return testbench.common.make_xml_preconditions(
            Request(
                create_environ(
                    base_url="http://localhost:8080",
                    content_length=0,
                    data="",
                    content_type="application/octet-stream",
                    method="POST",
                    headers=headers,
                    query_string={},
                )
            ),
        )

    def test_make_xml_preconditions_empty(self):
        preconditions = self.make_test_xml_preconditions({})
        self.assertEqual(len(preconditions), 0)

    def test_make_xml_preconditions_many(self):
        preconditions = self.make_test_xml_preconditions(
            {
                "x-goog-if-generation-match": 42,
                "x-goog-if-metageneration-match": 42,
            }
        )
        self.assertEqual(len(preconditions), 2)

    def test_make_xml_preconditions_if_generation_match(self):
        preconditions = self.make_test_xml_preconditions(
            {"x-goog-if-generation-match": 42}
        )
        self.assertEqual(len(preconditions), 1)
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=42))
        self.assertTrue(preconditions[0](blob, 42, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](blob, 43, None)
        self.assertEqual(rest.exception.code, 412)

        preconditions = self.make_test_xml_preconditions(
            {"x-goog-if-generation-match": 0}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, None, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=42))
            preconditions[0](blob, 42, None)
        self.assertEqual(rest.exception.code, 412)

    def test_make_xml_preconditions_if_metageneration_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=42))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=43))

        preconditions = self.make_test_xml_preconditions(
            {"x-goog-if-metageneration-match": 42}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b0, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, 3, None)
        self.assertEqual(rest.exception.code, 412)

        preconditions = self.make_test_xml_preconditions(
            {"x-goog-if-metageneration-match": 0}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, 3, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, 3, None)
        self.assertEqual(rest.exception.code, 412)

    def make_grpc_preconditions(self, **kwargs):
        """Helper function to test gRPC preconditions."""
        return testbench.common.make_grpc_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                **kwargs,
            )
        )

    def test_make_grpc_preconditions_empty(self):
        preconditions = self.make_grpc_preconditions()
        self.assertEqual(len(preconditions), 0)

    def test_make_grpc_preconditions_request_types(self):
        preconditions = self.make_grpc_preconditions(
            if_generation_match=5,
            if_generation_not_match=5,
            if_metageneration_match=5,
            if_metageneration_not_match=5,
        )
        self.assertEqual(len(preconditions), 4)

        preconditions = testbench.common.make_grpc_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_match=5,
                if_generation_not_match=5,
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

        preconditions = testbench.common.make_grpc_preconditions(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_match=5,
                if_generation_not_match=5,
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

        preconditions = testbench.common.make_grpc_preconditions(
            storage_pb2.UpdateObjectRequest(
                object=storage_pb2.Object(
                    bucket="projects/_/buckets/bucket-name", name="object-name"
                ),
                if_generation_match=5,
                if_generation_not_match=5,
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

        preconditions = testbench.common.make_grpc_preconditions(
            request=storage_pb2.RewriteObjectRequest(
                destination=storage_pb2.Object(
                    bucket="projects/_/buckets/bucket-name", name="object-name"
                ),
                source_bucket="projects/_/buckets/bucket-name",
                source_object="destination-object-name",
                if_generation_match=5,
                if_generation_not_match=5,
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

    def test_make_grpc_preconditions_source(self):
        preconditions = testbench.common.make_grpc_preconditions(
            prefix="if_source_",
            request=storage_pb2.RewriteObjectRequest(
                destination=storage_pb2.Object(
                    bucket="projects/_/buckets/bucket-name", name="object-name"
                ),
                source_bucket="projects/_/buckets/bucket-name",
                source_object="destination-object-name",
                if_source_generation_match=5,
                if_source_generation_not_match=5,
                if_source_metageneration_match=5,
                if_source_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

    def test_make_grpc_preconditions_if_generation_match(self):
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))

        preconditions = self.make_grpc_preconditions(if_generation_match=5)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, 5, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, 6, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

        preconditions = self.make_grpc_preconditions(if_generation_match=0)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, None, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, 6, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_make_grpc_preconditions_if_generation_not_match(self):
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))

        preconditions = self.make_grpc_preconditions(if_generation_not_match=5)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, 6, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, 5, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

        preconditions = self.make_grpc_preconditions(if_generation_not_match=0)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, 6, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, None, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

    def test_make_grpc_preconditions_if_metageneration_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6))

        preconditions = self.make_grpc_preconditions(if_metageneration_match=5)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b0, 3, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b1, 3, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

        preconditions = self.make_grpc_preconditions(if_metageneration_match=0)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](None, 3, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b0, 3, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_make_grpc_preconditions_if_metageneration_not_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6))

        preconditions = self.make_grpc_preconditions(if_metageneration_not_match=5)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b1, 3, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b0, 3, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

        preconditions = self.make_grpc_preconditions(if_metageneration_not_match=0)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b0, 3, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](None, 3, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

    def make_test_json_bucket_preconditions(self, query_string):
        """Helper function to test JSON bucket preconditions."""
        return testbench.common.make_json_bucket_preconditions(
            Request(
                create_environ(
                    base_url="http://localhost:8080",
                    content_length=2,
                    data="{}",
                    content_type="application/json",
                    method="POST",
                    headers={},
                    query_string=query_string,
                )
            ),
        )

    def test_make_json_bucket_preconditions_empty(self):
        preconditions = self.make_test_json_bucket_preconditions({})
        self.assertEqual(len(preconditions), 0)

    def test_make_json_bucket_preconditions_many(self):
        preconditions = self.make_test_json_bucket_preconditions(
            {
                "ifMetagenerationMatch": "5",
                "ifMetagenerationNotMatch": "5",
            }
        )
        self.assertEqual(len(preconditions), 2)

    def test_make_json_bucket_preconditions_if_metageneration_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=6))

        preconditions = self.make_test_json_bucket_preconditions(
            {"ifMetagenerationMatch": "5"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b0, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, None)
        self.assertEqual(rest.exception.code, 412)

        preconditions = self.make_test_json_bucket_preconditions(
            {"ifMetagenerationMatch": "0"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](None, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b1, None)
        self.assertEqual(rest.exception.code, 412)

    def test_make_json_bucket_preconditions_if_metageneration_not_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=6))

        preconditions = self.make_test_json_bucket_preconditions(
            {"ifMetagenerationNotMatch": "5"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b1, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](b0, None)
        self.assertEqual(rest.exception.code, 304)

        preconditions = self.make_test_json_bucket_preconditions(
            {"ifMetagenerationNotMatch": "0"}
        )
        self.assertEqual(len(preconditions), 1)
        self.assertTrue(preconditions[0](b0, None))

        with self.assertRaises(testbench.error.RestException) as rest:
            preconditions[0](None, None)
        self.assertEqual(rest.exception.code, 304)

    def make_grpc_bucket_preconditions(self, **kwargs):
        """Helper function to test gRPC preconditions."""
        return testbench.common.make_grpc_bucket_preconditions(
            storage_pb2.GetBucketRequest(
                name="projects/_/buckets/bucket-name",
                **kwargs,
            )
        )

    def test_make_grpc_bucket_preconditions_empty(self):
        preconditions = self.make_grpc_bucket_preconditions()
        self.assertEqual(len(preconditions), 0)

    def test_make_grpc_bucket_preconditions_request_types(self):
        preconditions = self.make_grpc_bucket_preconditions(
            if_metageneration_match=5,
            if_metageneration_not_match=5,
        )
        self.assertEqual(len(preconditions), 2)

        preconditions = testbench.common.make_grpc_bucket_preconditions(
            storage_pb2.GetBucketRequest(
                name="projects/_/buckets/bucket-name",
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 2)

        preconditions = testbench.common.make_grpc_bucket_preconditions(
            storage_pb2.DeleteBucketRequest(
                name="projects/_/buckets/bucket-name",
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 2)

        preconditions = testbench.common.make_grpc_bucket_preconditions(
            storage_pb2.UpdateBucketRequest(
                bucket=storage_pb2.Bucket(name="projects/_/buckets/bucket-name"),
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 2)

    def test_make_grpc_bucket_preconditions_if_metageneration_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=6))

        preconditions = self.make_grpc_bucket_preconditions(if_metageneration_match=5)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b0, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b1, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

        preconditions = self.make_grpc_bucket_preconditions(if_metageneration_match=0)
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](None, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b0, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_make_grpc_bucket_preconditions_if_metageneration_not_match(self):
        b0 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=5))
        b1 = types.SimpleNamespace(metadata=storage_pb2.Bucket(metageneration=6))

        preconditions = self.make_grpc_bucket_preconditions(
            if_metageneration_not_match=5
        )
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b1, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](b0, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

        preconditions = self.make_grpc_bucket_preconditions(
            if_metageneration_not_match=0
        )
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](b0, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](None, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
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
        #    gsutil hash fox.txt
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

    def test_md5_to_from_proto(self):
        # used an external tool to get the CRC32C of:
        #    /bin/echo -n 'The quick brown fox jumps over the lazy dog' > fox.txt
        #    gsutil hash fox.txt
        # it prints
        #    Hash (md5):		nhB9nTcrtoJr2B01QqQZ1g==
        # then use:
        #    echo nhB9nTcrtoJr2B01QqQZ1g== | openssl base64 -d | xxd -p
        # that prints
        #    9e107d9d372bb6826bd81d3542a419d6
        self.assertEqual(
            b"\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6",
            testbench.common.rest_md5_to_proto("nhB9nTcrtoJr2B01QqQZ1g=="),
        )
        self.assertEqual(
            "nhB9nTcrtoJr2B01QqQZ1g==",
            testbench.common.rest_md5_from_proto(
                b"\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6"
            ),
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

    def test_rest_patch(self):
        TEST_CASES = [
            {
                "resource": {"a": "x", "b": "y"},
                "patch": {"a": "z"},
                "expected": {"a": "z", "b": "y"},
            },
            {
                "resource": {"a": "x", "b": "y"},
                "patch": {"a": None},
                "expected": {"b": "y"},
            },
            {
                "resource": {"a": {"c": 42}, "b": "y"},
                "patch": {"a": None},
                "expected": {"b": "y"},
            },
            {
                "resource": {"a": "x", "b": {"c": {"d": 7}}},
                "patch": {"b": {"e": "add-e", "c": {"d": 42}}},
                "expected": {"a": "x", "b": {"e": "add-e", "c": {"d": 42}}},
            },
        ]
        for index, test in enumerate(TEST_CASES):
            self.assertEqual(
                test["expected"],
                testbench.common.rest_patch(test["resource"], test["patch"]),
                msg="Entry %d" % index,
            )

        with self.assertRaises(Exception) as ex:
            testbench.common.rest_patch({"a": {"b": "c"}}, {"a": {"b": {"ooops": 7}}})
        self.assertIn("Type mismatch at a.b", "%s" % ex.exception)

    def test_bucket_to_from_proto(self):
        self.assertIsNone(testbench.common.bucket_name_from_proto(None))
        self.assertEqual(
            "bucket-name", testbench.common.bucket_name_from_proto("bucket-name")
        )
        self.assertEqual(
            "bucket-name",
            testbench.common.bucket_name_from_proto("projects/_/buckets/bucket-name"),
        )
        self.assertEqual(
            "bucket-name",
            testbench.common.bucket_name_from_proto(
                testbench.common.bucket_name_to_proto("bucket-name")
            ),
        )
        self.assertEqual(
            "bucket.example.com",
            testbench.common.bucket_name_from_proto(
                testbench.common.bucket_name_to_proto("bucket.example.com")
            ),
        )


if __name__ == "__main__":
    unittest.main()
