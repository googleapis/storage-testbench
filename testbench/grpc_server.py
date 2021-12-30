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
import datetime

import crc32c
from google.iam.v1 import iam_policy_pb2
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
        self.db.insert_test_bucket()

    def DeleteBucket(self, request, context):
        self.db.delete_bucket(
            request.name,
            context=context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return empty_pb2.Empty()

    def GetBucket(self, request, context):
        bucket = self.db.get_bucket(
            request.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return bucket.metadata

    def CreateBucket(self, request, context):
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.db.insert_bucket(bucket, context)
        return bucket.metadata

    def ListBuckets(self, request, context):
        if not request.parent.startswith("projects/"):
            return testbench.error.invalid(
                "invalid format for parent=%s" % request.parent, context
            )
        project = request.parent[len("projects/") :]
        if len(request.read_mask.paths) == 0:
            # By default we need to filter out `acl`, `default_object_acl`, and `owner`
            def filter(bucket):
                b = storage_pb2.Bucket()
                b.CopyFrom(bucket)
                b.ClearField("acl")
                b.ClearField("default_object_acl")
                b.ClearField("owner")
                return b

        elif request.read_mask.paths == ["*"]:

            def filter(bucket):
                b = storage_pb2.Bucket()
                b.CopyFrom(bucket)
                return b

        else:

            def filter(bucket):
                b = storage_pb2.Bucket()
                request.read_mask.MergeMessage(bucket, b)
                return b

        buckets = [filter(b.metadata) for b in self.db.list_bucket(project, context)]
        return storage_pb2.ListBucketsResponse(buckets=buckets)

    def LockBucketRetentionPolicy(self, request, context):
        if request.if_metageneration_match <= 0:
            return testbench.error.invalid(
                "invalid metageneration precondition=%d"
                % request.if_metageneration_match,
                context,
            )

        # We cannot use testbench.common.make_grpc_bucket_precondition because
        # the if_metageneration_match field is non-optional and there is no *_not_match field.
        def precondition(bucket, ctx):
            actual = bucket.metadata.metageneration if bucket is not None else 0
            if request.if_metageneration_match == actual:
                return True
            return testbench.error.mismatch(
                "if_metageneration_match",
                expect=request.if_metageneration_match,
                actual=actual,
                context=ctx,
            )

        bucket = self.db.get_bucket(
            request.bucket, context, preconditions=[precondition]
        )
        bucket.metadata.retention_policy.is_locked = True
        bucket.metadata.retention_policy.effective_time.FromDatetime(
            datetime.datetime.now()
        )
        return bucket.metadata

    def GetIamPolicy(self, request, context):
        bucket = self.db.get_bucket(request.resource, context)
        return bucket.iam_policy

    def SetIamPolicy(self, request, context):
        bucket = self.db.get_bucket(request.resource, context)
        bucket.set_iam_policy(request, context)
        return bucket.iam_policy

    def TestIamPermissions(self, request, context):
        # If the bucket does not exist this will return an error
        _ = self.db.get_bucket(request.resource, context)
        # We do not implement IAM functionality, just return something moderately sensible:
        return iam_policy_pb2.TestIamPermissionsResponse(
            permissions=[p for p in request.permissions if p.startswith("storage.")]
        )

    def UpdateBucket(self, request, context):
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
        self.db.delete_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        return empty_pb2.Empty()

    def GetObject(self, request, context):
        blob = self.db.get_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        return blob.metadata

    def ReadObject(self, request, context):
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
        items, prefixes = self.db.list_object(request, request.parent, context)
        return storage_pb2.ListObjectsResponse(objects=items, prefixes=prefixes)

    def RewriteObject(self, request, context):
        token = request.rewrite_token
        if token == "":
            rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
            self.db.insert_rewrite(rewrite)
        else:
            rewrite = self.db.get_rewrite(token, context)
        src_object = self.db.get_object(
            rewrite.request.source_bucket,
            rewrite.request.source_object,
            generation=rewrite.request.source_generation,
            preconditions=testbench.common.make_grpc_preconditions(
                rewrite.request, prefix="if_source_"
            ),
            context=context,
        )
        testbench.csek.validation(
            rewrite.request,
            src_object.metadata.customer_encryption.key_sha256_bytes,
            is_source=True,
            context=context,
        )
        total_bytes_rewritten = len(rewrite.media)
        total_bytes_rewritten += min(
            rewrite.max_bytes_rewritten_per_call,
            len(src_object.media) - len(rewrite.media),
        )
        rewrite.media += src_object.media[len(rewrite.media) : total_bytes_rewritten]
        done, dst_object = total_bytes_rewritten == len(src_object.media), None
        response = storage_pb2.RewriteResponse(
            total_bytes_rewritten=total_bytes_rewritten,
            object_size=len(src_object.media),
            done=done,
        )
        if not done:
            response.rewrite_token = rewrite.token
        else:
            dst_bucket_name = rewrite.request.destination.bucket
            dst_object_name = rewrite.request.destination.name
            dst_bucket = self.db.get_bucket(dst_bucket_name, context).metadata
            dst_metadata = storage_pb2.Object()
            dst_metadata.CopyFrom(src_object.metadata)
            # TODO(#227) - merge request and source object metadata
            dst_metadata.bucket = dst_bucket_name
            dst_metadata.name = dst_object_name
            dst_metadata.metageneration = 1
            dst_metadata.update_time.FromDatetime(dst_metadata.create_time.ToDatetime())
            dst_media = rewrite.media
            dst_object, _ = gcs.object.Object.init(
                rewrite.request,
                dst_metadata,
                dst_media,
                dst_bucket,
                is_destination=True,
                context=context,
            )
            self.db.insert_object(
                dst_bucket_name,
                dst_object,
                context=context,
                preconditions=testbench.common.make_grpc_preconditions(rewrite.request),
            )
            response.resource.CopyFrom(dst_metadata)

        return response

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

    def GetServiceAccount(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)
        return storage_pb2.ServiceAccount(email_address=project.service_account_email())


def run(port, database):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    storage_pb2_grpc.add_StorageServicer_to_server(StorageServicer(database), server)
    port = server.add_insecure_port("localhost:%d" % port)
    server.start()
    return port, server
