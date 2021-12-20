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

    def GetBucket(self, request, context):
        self.db.insert_test_bucket()
        bucket = self.db.get_bucket(request, request.name, context)
        return bucket.metadata

    def CreateBucket(self, request, context):
        self.db.insert_test_bucket()
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.db.insert_bucket(request, bucket, context)
        return bucket.metadata

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
        bucket = self.db.get_bucket(request, request.bucket.name, context)
        request.update_mask.MergeMessage(
            request.bucket, bucket.metadata, replace_repeated_field=True
        )
        return bucket.metadata

    def DeleteObject(self, request, context):
        self.db.insert_test_bucket()
        self.db.delete_object(request, request.bucket, request.object, context)
        return empty_pb2.Empty()

    def GetObject(self, request, context):
        blob = self.db.get_object(
            request, request.bucket, request.object, False, context
        )
        return blob.metadata

    def ReadObject(self, request, context):
        blob = self.db.get_object(
            request, request.bucket, request.object, False, context
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

    def __get_bucket(self, bucket_name, context) -> storage_pb2.Bucket:
        return self.db.get_bucket_without_generation(bucket_name, context).metadata

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
        self.db.insert_object(upload.request, upload.bucket.name, blob, context)
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
