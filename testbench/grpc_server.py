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

import base64
from collections.abc import Iterable
from concurrent import futures
import functools
import datetime
import json
import re
import uuid
import types

import crc32c
from google.iam.v1 import iam_policy_pb2
from google.storage.v2 import storage_pb2, storage_pb2_grpc
from google.protobuf import field_mask_pb2, json_format, text_format
import google.protobuf.empty_pb2 as empty_pb2
import grpc

import gcs
import testbench


def _format(message):
    text = text_format.MessageToString(
        message, as_one_line=True, use_short_repeated_primitives=True
    )
    return text[0:255]


def _format_input_generator(name, id, generator):
    for value in generator:
        print(
            "%s: %s generator[%s] <- %s"
            % (datetime.datetime.now(), name, id, _format(value))
        )
        yield value


def _format_output_generator(name, id, generator):
    for value in generator:
        print(
            "%s: %s generator[%s] -> %s"
            % (datetime.datetime.now(), name, id, _format(value))
        )
        yield value


def _logging_method_decorator(function):
    """
    Log the request and response from an RPC, returning the response.

    Returning the response makes the code more succint at the call site, without
    much loss of readability.

    Note that some functions (streaming RPCs mostly), cannot log their inputs
    or outputs as they are too large.
    """

    @functools.wraps(function)
    def decorated(self, request, context):
        if isinstance(request, (types.GeneratorType, Iterable)):
            id = uuid.uuid4().hex
            input = "in[" + id + "]"
            request = _format_input_generator(function.__name__, id, request)
        else:
            input = None if request is None else _format(request)
        response = None
        try:
            response = function(self, request, context)
            if isinstance(response, (types.GeneratorType, Iterable)):
                id = uuid.uuid4().hex
                output = "out[" + id + "]"
                response = _format_output_generator(function.__name__, id, response)
            else:
                output = None if response is None else _format(response)
        except Exception as e:
            output = "%s" % e
            raise
        finally:
            print(
                "%s: %s(%s) -> %s"
                % (datetime.datetime.now(), function.__name__, input, output)
            )
        return response

    return decorated


def _metadata_echo_decorator(function):
    """
    Send back the invocation metadata as initial metadata, if metadata echo is
    enabled.
    """

    @functools.wraps(function)
    def decorated(self, request, context):
        if self.echo_metadata:
            req_metadata = context.invocation_metadata()
            resp_metadata = list(
                map(lambda md: ("x-req-" + md[0], md[1]), req_metadata)
            )
            context.send_initial_metadata(resp_metadata)
        return function(self, request, context)

    return decorated


def decorate_all_rpc_methods(klass):
    """Decorate all the RPC-looking methods."""
    for key in dir(klass):
        if key.startswith("_"):
            continue
        value = getattr(klass, key)
        if isinstance(value, types.FunctionType):
            wrapped = _metadata_echo_decorator(value)
            wrapped = _logging_method_decorator(wrapped)
            setattr(klass, key, wrapped)
    return klass


# Keep the methods in this class in the same order as the RPCs in storage.proto.
# That makes it easier to find them later.
@decorate_all_rpc_methods
class StorageServicer(storage_pb2_grpc.StorageServicer):
    """Implements the google.storage.v2.Storage gRPC service."""

    def __init__(self, db, echo_metadata=False):
        self.db = db
        self.db.insert_test_bucket()
        self.echo_metadata = echo_metadata

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
        prefix = request.prefix

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

        buckets = [
            filter(b.metadata) for b in self.db.list_bucket(project, prefix, context)
        ]
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
        # We do not implement IAM functionality, just echo the request permissions back:
        return iam_policy_pb2.TestIamPermissionsResponse(
            permissions=request.permissions
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
        if not request.update_mask.IsValidForDescriptor(storage_pb2.Bucket.DESCRIPTOR):
            return testbench.error.invalid(
                "UpdateBucket() invalid field for Bucket [%s]"
                % ",".join(intersection.paths),
                context,
            )
        bucket = self.db.get_bucket(
            request.bucket.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        # TODO(#270) - cleanup the manual steps
        paths = set(request.update_mask.paths)
        safe_paths = paths.copy()
        safe_paths.discard("acl")
        safe_paths.discard("default_object_acl")
        safe_paths.discard("labels")
        mask = field_mask_pb2.FieldMask()
        mask.paths[:] = list(safe_paths)
        mask.MergeMessage(request.bucket, bucket.metadata)
        # Manually replace the repeated fields.
        if "acl" in request.update_mask.paths:
            del bucket.metadata.acl[:]
            bucket.metadata.acl.extend(request.bucket.acl)
        if "default_object_acl" in request.update_mask.paths:
            del bucket.metadata.default_object_acl[:]
            bucket.metadata.default_object_acl.extend(request.bucket.default_object_acl)
        if "labels" in request.update_mask.paths:
            bucket.metadata.labels.clear()
            bucket.metadata.labels.update(request.bucket.labels)
        bucket.metadata.metageneration += 1
        bucket.metadata.update_time.FromDatetime(datetime.datetime.now())
        return bucket.metadata

    def _notification_from_rest(self, rest, bucket_name):
        # We need to make a copy before changing any values
        rest = rest.copy()
        rest.pop("kind")
        rest["name"] = bucket_name + "/notificationConfigs/" + rest.pop("id")
        rest["topic"] = "//pubsub.googleapis.com/" + rest["topic"]
        return json_format.ParseDict(rest, storage_pb2.Notification())

    def _decompose_notification_name(self, notification_name, context):
        loc = notification_name.find("/notificationConfigs/")
        if loc == -1:
            testbench.error.invalid(
                "GetNotification() malformed notification name [%s]"
                % notification_name,
                context,
            )
            return (None, None)
        bucket_name = notification_name[:loc]
        notification_id = notification_name[loc + len("/notificationConfigs/") :]
        return (bucket_name, notification_id)

    def DeleteNotification(self, request, context):
        bucket_name, notification_id = self._decompose_notification_name(
            request.name, context
        )
        if bucket_name is None:
            return None
        bucket = self.db.get_bucket(bucket_name, context)
        bucket.delete_notification(notification_id, context)
        return empty_pb2.Empty()

    def GetNotification(self, request, context):
        bucket_name, notification_id = self._decompose_notification_name(
            request.name, context
        )
        if bucket_name is None:
            return None
        bucket = self.db.get_bucket(bucket_name, context)
        rest = bucket.get_notification(notification_id, context)
        return self._notification_from_rest(rest, bucket_name)

    def CreateNotification(self, request, context):
        pattern = "^//pubsub.googleapis.com/projects/[^/]+/topics/[^/]+$"
        if re.match(pattern, request.notification.topic) is None:
            return testbench.error.invalid(
                "topic names must be in"
                + " //pubsub.googleapis.com/projects/{project-identifier}/topics/{my-topic}"
                + " format, got=%s" % request.notification.topic,
                context,
            )
        bucket = self.db.get_bucket(request.parent, context)
        notification = json_format.MessageToDict(request.notification)
        # Convert topic names to REST format
        notification["topic"] = notification["topic"][len("//pubsub.googleapis.com/") :]
        rest = bucket.insert_notification(json.dumps(notification), context)
        return self._notification_from_rest(rest, request.parent)

    def ListNotifications(self, request, context):
        bucket = self.db.get_bucket(request.parent, context)
        items = bucket.list_notifications(context).get("items", [])
        return storage_pb2.ListNotificationsResponse(
            notifications=[
                self._notification_from_rest(r, request.parent) for r in items
            ]
        )

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

    def CancelResumableWrite(self, request, context):
        self.db.delete_upload(request.upload_id, context)
        return storage_pb2.CancelResumableWriteResponse()

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
        if not request.update_mask.IsValidForDescriptor(storage_pb2.Object.DESCRIPTOR):
            return testbench.error.invalid(
                "UpdateObject() invalid field for Object [%s]"
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
        # TODO(#270) - cleanup the manual steps
        paths = set(request.update_mask.paths)
        safe_paths = paths.copy()
        safe_paths.discard("acl")
        safe_paths.discard("metadata")
        mask = field_mask_pb2.FieldMask()
        mask.paths[:] = list(safe_paths)
        mask.MergeMessage(request.object, blob.metadata)
        # Manually replace the repeated fields.
        if "acl" in request.update_mask.paths:
            del blob.metadata.acl[:]
            blob.metadata.acl.extend(request.object.acl)
        if "metadata" in request.update_mask.paths:
            blob.metadata.metadata.clear()
            blob.metadata.metadata.update(request.object.metadata)
        # Manually handle predefinedACL.
        if request.predefined_acl:
            acls = testbench.acl.compute_predefined_object_acl(
                request.object.bucket,
                request.object.name,
                request.object.generation,
                request.predefined_acl,
                context,
            )
            del blob.metadata.acl[:]
            blob.metadata.acl.extend(acls)
        blob.metadata.metageneration += 1
        blob.metadata.update_time.FromDatetime(datetime.datetime.now())
        return blob.metadata

    def __get_bucket(self, bucket_name, context) -> storage_pb2.Bucket:
        return self.db.get_bucket(bucket_name, context).metadata

    def WriteObject(self, request_iterator, context):
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            self.db, request_iterator, context
        )
        if upload is None:
            return None
        if not upload.complete:
            if not is_resumable:
                return testbench.error.missing("finish_write in request", context)
            return storage_pb2.WriteObjectResponse(persisted_size=len(upload.media))
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
        return storage_pb2.WriteObjectResponse(resource=blob.metadata)

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
            return response

        dst_bucket_name = rewrite.request.destination_bucket
        dst_object_name = rewrite.request.destination_name
        dst_bucket = self.db.get_bucket(dst_bucket_name, context).metadata
        dst_metadata = storage_pb2.Object()
        if rewrite.request.HasField("destination"):
            dst_metadata.CopyFrom(rewrite.request.destination)
        else:
            dst_metadata.CopyFrom(src_object.metadata)
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
        return storage_pb2.StartResumableWriteResponse(upload_id=upload.upload_id)

    def QueryWriteStatus(self, request, context):
        upload = self.db.get_upload(request.upload_id, context)
        if upload.complete:
            return storage_pb2.QueryWriteStatusResponse(resource=upload.blob.metadata)
        return storage_pb2.QueryWriteStatusResponse(persisted_size=len(upload.media))

    def GetServiceAccount(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)
        return storage_pb2.ServiceAccount(email_address=project.service_account_email())

    def _hmac_key_metadata_from_rest(self, rest):
        rest = rest.copy()
        rest.pop("kind", None)
        rest["project"] = "projects/" + rest.pop("projectId")
        rest["create_time"] = rest.pop("timeCreated")
        rest["update_time"] = rest.pop("updated")
        return json_format.ParseDict(rest, storage_pb2.HmacKeyMetadata())

    def CreateHmacKey(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        if request.service_account_email == "":
            return testbench.error.invalid(
                "service account email must be non-empty", context
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)
        rest = project.insert_hmac_key(request.service_account_email)
        return storage_pb2.CreateHmacKeyResponse(
            secret_key_bytes=base64.b64decode(rest.get("secret").encode("utf-8")),
            metadata=self._hmac_key_metadata_from_rest(rest.get("metadata")),
        )

    def DeleteHmacKey(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)
        project.delete_hmac_key(request.access_id, context)
        return empty_pb2.Empty()

    def GetHmacKey(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)
        rest = project.get_hmac_key(request.access_id, context)
        return self._hmac_key_metadata_from_rest(rest)

    def ListHmacKeys(self, request, context):
        if not request.project.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % request.project,
                context,
            )
        project_id = request.project[len("projects/") :]
        project = self.db.get_project(project_id)

        items = []
        sa_email = request.service_account_email
        if len(sa_email) != 0:
            service_account = project.service_account(sa_email)
            if service_account:
                items = service_account.key_items()
        else:
            for sa in project.service_accounts.values():
                items.extend(sa.key_items())

        state_filter = lambda x: x.get("state") != "DELETED"
        if request.show_deleted_keys:
            state_filter = lambda x: True

        return storage_pb2.ListHmacKeysResponse(
            hmac_keys=[
                self._hmac_key_metadata_from_rest(i) for i in items if state_filter(i)
            ]
        )

    def UpdateHmacKey(self, request, context):
        if request.update_mask.paths == []:
            return testbench.error.invalid(
                "UpdateHmacKey() with an empty update mask", context
            )
        if request.update_mask.paths != ["state"]:
            return testbench.error.invalid(
                "UpdateHmacKey() only the `state` field can be modified [%s]"
                % ",".join(request.update_mask.paths),
                context,
            )
        project_id = request.hmac_key.project
        if not project_id.startswith("projects/"):
            return testbench.error.invalid(
                "project name must start with projects/, got=%s" % project_id, context
            )
        project_id = project_id[len("projects/") :]
        project = self.db.get_project(project_id)
        payload = {"state": request.hmac_key.state}
        if request.hmac_key.etag != "":
            payload["etag"] = request.hmac_key.etag
        rest = project.update_hmac_key(request.hmac_key.access_id, payload, context)
        return self._hmac_key_metadata_from_rest(rest)


def run(port, database, echo_metadata=False):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    storage_pb2_grpc.add_StorageServicer_to_server(
        StorageServicer(database, echo_metadata), server
    )
    port = server.add_insecure_port("0.0.0.0:%d" % port)
    server.start()
    return port, server
