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

"""Unit test for testbench.grpc."""

import json
import types
import unittest
import unittest.mock

import crc32c
import grpc
from google.protobuf import field_mask_pb2

import gcs
from google.storage.v2 import storage_pb2, storage_pb2_grpc
import testbench


class TestGrpc(unittest.TestCase):
    def setUp(self):
        self.db = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.db.insert_bucket(request, self.bucket, None)
        self.grpc = testbench.grpc_server.StorageServicer(self.db)

    def test_get_bucket(self):
        context = unittest.mock.Mock()
        response = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual(response.name, "projects/_/buckets/bucket-name")
        self.assertEqual(response.bucket_id, "bucket-name")
        self.assertEqual(response, self.bucket.metadata)

    def test_create_bucket(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(),
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateBucket(request, context)
        self.assertEqual(response.name, "projects/_/buckets/test-bucket-name")
        self.assertEqual(response.bucket_id, "test-bucket-name")

    def test_update_bucket(self):
        # First check the default bucket state.
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual("projects/_/buckets/bucket-name", get.name)
        self.assertEqual(dict(), get.labels)
        self.assertEqual("STANDARD", get.storage_class)
        self.assertEqual("DEFAULT", get.rpo)

        # Then change some properties, note that we set some attributes but not the
        # corresponding field mask, those should not change.
        context = unittest.mock.Mock()
        response = self.grpc.UpdateBucket(
            storage_pb2.UpdateBucketRequest(
                bucket=storage_pb2.Bucket(
                    name="projects/_/buckets/bucket-name",
                    labels={"key": "value"},
                    storage_class="NEARLINE",
                    rpo="ASYNC_TURBO",
                ),
                update_mask=field_mask_pb2.FieldMask(paths=["labels", "rpo"]),
            ),
            context,
        )
        self.assertEqual("projects/_/buckets/bucket-name", response.name)
        self.assertEqual({"key": "value"}, response.labels)
        self.assertEqual("STANDARD", response.storage_class)
        self.assertEqual("ASYNC_TURBO", response.rpo)

        # Finally verify the changes are persisted
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual("projects/_/buckets/bucket-name", get.name)
        self.assertEqual({"key": "value"}, get.labels)
        self.assertEqual("STANDARD", get.storage_class)
        self.assertEqual("ASYNC_TURBO", get.rpo)

    def test_update_bucket_invalid_masks(self):
        for invalid in [
            "name",
            "bucket_id",
            "project",
            "metageneration",
            "location",
            "location_type",
            "create_time",
            "update_time",
            "owner",
        ]:
            context = unittest.mock.Mock()
            _ = self.grpc.UpdateBucket(
                storage_pb2.UpdateBucketRequest(
                    bucket=storage_pb2.Bucket(name="projects/_/buckets/bucket-name"),
                    update_mask=field_mask_pb2.FieldMask(paths=[invalid]),
                ),
                context,
            )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_make_preconditions_empty(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
        )
        self.assertEqual(len(preconditions), 0)

    def test_make_preconditions_request_types(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.DeleteObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_match=5,
                if_generation_not_match=5,
                if_metageneration_match=5,
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 4)

        preconditions = self.grpc._make_preconditions(
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

        preconditions = self.grpc._make_preconditions(
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

        preconditions = self.grpc._make_preconditions(
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

    def test_make_preconditions_if_generation_match(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 1)
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, 5, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, 6, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_make_preconditions_if_generation_not_match(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 1)
        blob = types.SimpleNamespace(metadata=storage_pb2.Object(generation=5))
        context = unittest.mock.Mock()
        self.assertTrue(preconditions[0](blob, 6, context))
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(preconditions[0](blob, 5, context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

    def test_make_preconditions_if_metageneration_match(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_metageneration_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(
            preconditions[0](
                types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5)),
                3,
                context,
            )
        )
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(
            preconditions[0](
                types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6)),
                3,
                context,
            )
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_make_preconditions_if_metageneration_not_match(self):
        preconditions = self.grpc._make_preconditions(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_metageneration_not_match=5,
            ),
        )
        self.assertEqual(len(preconditions), 1)
        context = unittest.mock.Mock()
        self.assertTrue(
            preconditions[0](
                types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=6)),
                3,
                context,
            )
        )
        context.abort.assert_not_called()

        context = unittest.mock.Mock()
        self.assertFalse(
            preconditions[0](
                types.SimpleNamespace(metadata=storage_pb2.Object(metageneration=5)),
                3,
                context,
            )
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.ABORTED, unittest.mock.ANY
        )

    def test_delete_object(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        full_bucket_name = blob.metadata.bucket
        context = unittest.mock.Mock()
        _ = self.grpc.DeleteObject(
            storage_pb2.DeleteObjectRequest(
                bucket=full_bucket_name, object="object-name"
            ),
            context,
        )
        context = unittest.mock.Mock()
        items, _ = self.db.list_object(
            storage_pb2.ListObjectsRequest(parent=full_bucket_name),
            full_bucket_name,
            context,
        )
        names = {o.name for o in items}
        self.assertNotIn("object-name", names)

    def test_get_object(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual(response.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(response.name, "object-name")
        self.assertNotEqual(0, response.generation)
        self.assertEqual(response.size, len(media))

    @staticmethod
    def _create_block(desired_bytes):
        line = "A" * 127 + "\n"
        return int(desired_bytes / len(line)) * line

    def test_read_object(self):
        media = TestGrpc._create_block(5 * 1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            "fake-context",
        )
        chunks = [r for r in response]
        for i, c in enumerate(chunks):
            self.assertIsNotNone(c.checksummed_data, msg=i)
            self.assertEqual(
                crc32c.crc32c(c.checksummed_data.content),
                c.checksummed_data.crc32c,
                msg=i,
            )
        expected_sizes = [2 * 1024 * 1024, 2 * 1024 * 1024, 1 * 1024 * 1024]
        self.assertEqual(
            expected_sizes, [len(c.checksummed_data.content) for c in chunks]
        )
        self.assertEqual(
            crc32c.crc32c(media),
            crc32c.crc32c(b"".join([c.checksummed_data.content for c in chunks])),
        )

    def test_update_object(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.UpdateObject(
            storage_pb2.UpdateObjectRequest(
                object=storage_pb2.Object(
                    bucket="projects/_/buckets/bucket-name",
                    name="object-name",
                    metadata={"key": "value"},
                    content_type="text/plain",
                    cache_control="fancy cache",
                ),
                update_mask=field_mask_pb2.FieldMask(
                    paths=["content_type", "metadata"]
                ),
            ),
            context,
        )
        self.assertEqual("text/plain", response.content_type)
        self.assertEqual({"key": "value"}, response.metadata)
        self.assertEqual("", response.cache_control)

        # Verify the update is "persisted" as opposed to just changing the response
        context = unittest.mock.Mock()
        get = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual("text/plain", get.content_type)
        self.assertEqual({"key": "value"}, get.metadata)
        self.assertEqual("", get.cache_control)

    def test_update_object_invalid(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        for invalid in [
            "name",
            "bucket",
            "generation",
            "metageneration",
            "storage_class",
            "size",
            "delete_time",
            "create_time",
            "component_count",
            "checksums",
            "update_time",
            "kms_key",
            "update_storage_class_time",
            "owner",
            "customer_encryption",
        ]:
            context = unittest.mock.Mock(name="testing with path=" + invalid)
            _ = self.grpc.UpdateObject(
                storage_pb2.UpdateObjectRequest(
                    object=storage_pb2.Object(
                        bucket="projects/_/buckets/bucket-name",
                        name="object-name",
                    ),
                    update_mask=field_mask_pb2.FieldMask(paths=[invalid]),
                ),
                context,
            )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_object_write(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[QUANTUM:]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )

        write = self.grpc.WriteObject([r1, r2, r3], "fake-context")
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_object_write_invalid_request(self):
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_object_write_incomplete(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([r1], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_resumable_write(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context="fake-context",
        )
        self.assertIsNotNone(start.upload_id)

        def streamer():
            media = TestGrpc._create_block(517 * 1024).encode("utf-8")
            step = 256 * 1024
            end = min(step, len(media))
            content = media[0:end]
            # The first message is special, it should have a an upload id.
            yield storage_pb2.WriteObjectRequest(
                upload_id=start.upload_id,
                write_offset=0,
                checksummed_data=storage_pb2.ChecksummedData(
                    content=content, crc32c=crc32c.crc32c(content)
                ),
                finish_write=(end == len(media)),
            )

            for offset in range(step, len(media), step):
                end = min(offset + step, len(media))
                content = media[offset:end]
                yield storage_pb2.WriteObjectRequest(
                    write_offset=offset,
                    checksummed_data=storage_pb2.ChecksummedData(
                        content=content, crc32c=crc32c.crc32c(content)
                    ),
                    finish_write=(end == len(media)),
                )

        write = self.grpc.WriteObject(streamer(), "fake-context")
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_resumes(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )
        write = self.grpc.WriteObject([r1], "fake-context")
        self.assertIsNotNone(write)
        self.assertEqual(write.persisted_size, QUANTUM)

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertEqual(status.persisted_size, QUANTUM)

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[2 * QUANTUM :]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r2, r3], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_query_completed(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM:]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r1, r2], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

        # If the application crashes before checkpointing the upload status, it
        # may query the upload status on restart.  The testbench should return
        # the full object metadata.

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertTrue(status.HasField("resource"))
        blob = status.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(blob.size, len(media))

    def test_list_objects(self):
        names = ["a/test-0", "a/test-1", "a/b/test-0", "a/b/test-1", "c/test-0"]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object(request, "bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.ListObjects(
            storage_pb2.ListObjectsRequest(
                parent="projects/_/buckets/bucket-name",
                prefix="a/",
                delimiter="/",
            ),
            context,
        )
        self.assertEqual(response.prefixes, ["a/b/"])
        response_names = [o.name for o in response.objects]
        self.assertEqual(response_names, ["a/test-0", "a/test-1"])

    def test_list_objects_offsets(self):
        names = [
            "a/a/test-0",
            "a/b/test-1",
            "a/b/x/test-5",
            "a/b/x/test-6",
            "a/c/test-2",
            "a/d/test-3",
            "a/e/test-4",
        ]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object(request, "bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.ListObjects(
            storage_pb2.ListObjectsRequest(
                parent="projects/_/buckets/bucket-name",
                prefix="a/",
                lexicographic_start="a/b/",
                lexicographic_end="a/e/",
            ),
            context,
        )
        self.assertEqual(response.prefixes, [])
        response_names = [o.name for o in response.objects]
        self.assertEqual(
            response_names,
            [
                "a/b/test-1",
                "a/b/x/test-5",
                "a/b/x/test-6",
                "a/c/test-2",
                "a/d/test-3",
            ],
        )

    def test_list_objects_trailing_delimiters(self):
        names = [
            "a/a/",
            "a/a/test-0",
            "a/b/",
            "a/b/test-1",
            "a/c/test-2",
            "a/test-3",
        ]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object(request, "bucket-name", blob, None)
        cases = [
            {"include_trailing_delimiter": False, "expected": ["a/test-3"]},
            {
                "include_trailing_delimiter": True,
                "expected": ["a/a/", "a/b/", "a/test-3"],
            },
        ]
        for case in cases:
            context = unittest.mock.Mock()
            response = self.grpc.ListObjects(
                storage_pb2.ListObjectsRequest(
                    parent="projects/_/buckets/bucket-name",
                    prefix="a/",
                    delimiter="/",
                    include_trailing_delimiter=case["include_trailing_delimiter"],
                ),
                context,
            )
            self.assertEqual(response.prefixes, ["a/a/", "a/b/", "a/c/"])
            response_names = [o.name for o in response.objects]
            self.assertEqual(response_names, case["expected"], msg=case)

    def test_run(self):
        port, server = testbench.grpc_server.run(0, self.db)
        self.assertNotEqual(port, 0)
        self.assertIsNotNone(server)

        stub = storage_pb2_grpc.StorageStub(
            grpc.insecure_channel("localhost:%d" % port)
        )
        start = stub.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
        )
        self.assertIsNotNone(start.upload_id)
        self.assertNotEqual(start.upload_id, "")
        server.stop(grace=0)


if __name__ == "__main__":
    unittest.main()
