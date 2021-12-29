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

from concurrent import futures

import crc32c
from google.storage.v2 import storage_pb2, storage_pb2_grpc
from google.protobuf import field_mask_pb2, text_format
import google.protobuf.empty_pb2 as empty_pb2
import grpc

import gcs
import testbench


# Keep the methods in this class in the same order as the RPCs in storage.proto.
# That makes it easier to find them later.
class StorageServicer(storage_pb2_grpc.StorageServicer):
    """Implements the google.storage.v2.Storage gRPC service."""

    def __init__(self, db):
        self.db = db

    def DeleteBucket(self, request, context):
        self.db.insert_test_bucket()
        self.db.delete_bucket(
            request.name,
            context=context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return empty_pb2.Empty()

    def GetBucket(self, request, context):
        self.db.insert_test_bucket()
        bucket = self.db.get_bucket(
            request.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return bucket.metadata

    def CreateBucket(self, request, context):
        self.db.insert_test_bucket()
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.db.insert_bucket(bucket, context)
        return bucket.metadata

    def GetIamPolicy(self, request, context):
        self.db.insert_test_bucket()
        bucket = self.db.get_bucket(request.resource, context)
        return bucket.iam_policy

    def UpdateBucket(self, request, context):
        self.db.insert_test_bucket()
        intersection = field_mask_pb2.FieldMask(
            paths=[
                "name",
                "bucket_id",
                "project",
                "metageneration",
                "location",
                "location_type",
                "create_time",
                "update_time",
                "owner",
            ]
        )
        intersection.Intersect(intersection, request.update_mask)
        if len(intersection.paths) != 0:
            return testbench.error.invalid(
                "UpdateBucket() cannot modify immutable Bucket fields [%s]"
                % ",".join(intersection.paths),
                context,
            )
        bucket = self.db.get_bucket(
            request.bucket.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        request.update_mask.MergeMessage(
            request.bucket, bucket.metadata, replace_repeated_field=True
        )
        return bucket.metadata

    def ComposeObject(self, request, context):
        self.db.insert_test_bucket()
        if len(request.source_objects) == 0:
            return testbench.error.missing(
                "missing or empty source_objects attribute", context
            )
        if len(request.destination.name) == 0:
            return testbench.error.missing(
                "missing or empty destination object name", context
            )
        if len(request.destination.bucket) == 0:
            return testbench.error.missing(
                "missing or empty destination bucket name", context
            )
        if len(request.source_objects) > 32:
            return testbench.error.invalid(
                "The number of source components provided (%d > 32)"
                % len(request.source_objects),
                context,
            )
        composed_media = b""
        for source in request.source_objects:
            if len(source.name) == 0:
                return testbench.error.missing("Name of source compose object", context)

            if_generation_match = None
            if source.HasField(
                "object_preconditions"
            ) and source.object_preconditions.HasField("if_generation_match"):
                if_generation_match = source.object_preconditions.if_generation_match

            def precondition(_, live_version, ctx):
                if if_generation_match is None or if_generation_match == live_version:
                    return True
                return testbench.error.mismatch(
                    "compose.ifGenerationMatch",
                    expect=if_generation_match,
                    actual=live_version,
                    context=ctx,
                )

            source_blob = self.db.get_object(
                request.destination.bucket,
                source.name,
                generation=source.generation,
                context=context,
                preconditions=[precondition],
            )
            if source_blob is None:
                return None
            composed_media += source_blob.media

        bucket = self.db.get_bucket(request.destination.bucket, context).metadata
        metadata = storage_pb2.Object()
        metadata.MergeFrom(request.destination)
        (blob, _,) = gcs.object.Object.init(
            request, metadata, composed_media, bucket, True, context
        )
        self.db.insert_object(
            request.destination.bucket,
            blob,
            context=context,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        return blob.metadata

    def DeleteObject(self, request, context):
        self.db.insert_test_bucket()
        self.db.delete_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        return empty_pb2.Empty()

    def GetObject(self, request, context):
        self.db.insert_test_bucket()
        blob = self.db.get_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        return blob.metadata

    def ReadObject(self, request, context):
        self.db.insert_test_bucket()
        blob = self.db.get_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        size = storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES
        is_first = True
        for start in range(0, len(blob.media), size):
            end = min(start + size, len(blob.media))
            chunk = blob.media[start:end]
            meta = blob.metadata if is_first else None
            is_first = False
            yield storage_pb2.ReadObjectResponse(
                checksummed_data={
                    "content": chunk,
                    "crc32c": crc32c.crc32c(chunk),
                },
                metadata=meta,
            )

    def UpdateObject(self, request, context):
        self.db.insert_test_bucket()
        intersection = field_mask_pb2.FieldMask(
            paths=[
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
            ]
        )
        intersection.Intersect(intersection, request.update_mask)
        if len(intersection.paths) != 0:
            return testbench.error.invalid(
                "UpdateObject() cannot modify immutable Object fields [%s]"
                % ",".join(intersection.paths),
                context,
            )
        self.db.insert_test_bucket()
        blob = self.db.get_object(
            request.object.bucket,
            request.object.name,
            context=context,
            generation=request.object.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        request.update_mask.MergeMessage(
            request.object, blob.metadata, replace_repeated_field=True
        )
        return blob.metadata

    def __get_bucket(self, bucket_name, context) -> storage_pb2.Bucket:
        return self.db.get_bucket(bucket_name, context).metadata

    @staticmethod
    def _format(message):
        return text_format.MessageToString(
            message, as_one_line=True, use_short_repeated_primitives=True
        )

    @staticmethod
    def _log_rpc_passthrough(function, request, response):
        """
        Log the request and response from an RPC, returning the response.

        Returning the response makes the code more succint at the call site, without
        much loss of readability.

        Note that some functions (streaming RPCs mostly), cannot log their inputs
        or outputs as they are too large.
        """
        input = None if request is None else StorageServicer._format(request)
        output = None if response is None else StorageServicer._format(response)
        print("GRPC %s(%s) -> %s" % (function, input, output))
        return response

    def WriteObject(self, request_iterator, context):
        self.db.insert_test_bucket()
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            self.db, request_iterator, context
        )
        if upload is None:
            return None
        if not upload.complete:
            if not is_resumable:
                return testbench.error.missing("finish_write in request", context)
            return StorageServicer._log_rpc_passthrough(
                "WriteObject",
                None,
                storage_pb2.WriteObjectResponse(persisted_size=len(upload.media)),
            )
        blob, _ = gcs.object.Object.init(
            upload.request, upload.metadata, upload.media, upload.bucket, False, context
        )
        upload.blob = blob
        self.db.insert_object(
            upload.bucket.name,
            blob,
            context=context,
            preconditions=upload.preconditions,
        )
        return StorageServicer._log_rpc_passthrough(
            "WriteObject", None, storage_pb2.WriteObjectResponse(resource=blob.metadata)
        )

    def ListObjects(self, request, context):
        self.db.insert_test_bucket()
        items, prefixes = self.db.list_object(request, request.parent, context)
        return storage_pb2.ListObjectsResponse(objects=items, prefixes=prefixes)

    def StartResumableWrite(self, request, context):
        bucket = self.__get_bucket(request.write_object_spec.resource.bucket, context)
        upload = gcs.upload.Upload.init_resumable_grpc(request, bucket, context)
        self.db.insert_upload(upload)
        return StorageServicer._log_rpc_passthrough(
            "StartResumableWrite",
            request,
            storage_pb2.StartResumableWriteResponse(upload_id=upload.upload_id),
        )

    def QueryWriteStatus(self, request, context):
        upload = self.db.get_upload(request.upload_id, context)
        if upload.complete:
            return StorageServicer._log_rpc_passthrough(
                "QueryWriteStatus",
                request,
                storage_pb2.QueryWriteStatusResponse(resource=upload.blob.metadata),
            )
        return StorageServicer._log_rpc_passthrough(
            "QueryWriteStatus",
            request,
            storage_pb2.QueryWriteStatusResponse(persisted_size=len(upload.media)),
        )


def run(port, database):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    storage_pb2_grpc.add_StorageServicer_to_server(StorageServicer(database), server)
    port = server.add_insecure_port("localhost:%d" % port)
    server.start()
    return port, server
