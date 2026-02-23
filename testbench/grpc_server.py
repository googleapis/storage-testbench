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
import copy
import datetime
import functools
import itertools
import json
import re
import sys
import types
import uuid
from collections.abc import Iterable
from concurrent import futures
from threading import Timer

import crc32c
import google.protobuf.any_pb2 as any_pb2
import google.protobuf.descriptor as pb_descriptor
import google.protobuf.empty_pb2 as empty_pb2
import google.protobuf.message as pb_message
import grpc
from google.protobuf import field_mask_pb2, json_format, text_format
from google.rpc import status_pb2
from grpc_status import rpc_status

import gcs
import testbench
from google.iam.v1 import iam_policy_pb2
from google.storage.v2 import storage_pb2, storage_pb2_grpc


def _trimmed_content(content):
    if len(content) > 10:
        content = content[:7]
        content += b"..."
    return content


def _trim_content_fields(message):
    for field, value in list(message.ListFields()):
        if (
            field.name == "content"
            and field.type == pb_descriptor.FieldDescriptor.TYPE_BYTES
        ):
            if field.label == pb_descriptor.FieldDescriptor.LABEL_REPEATED:
                message.content = [_trimmed_content(v) for v in value]
            else:
                message.content = _trimmed_content(value)
            continue

        if field.label == pb_descriptor.FieldDescriptor.LABEL_REPEATED:
            vals = value
        else:
            vals = [value]
        for v in vals:
            if isinstance(v, pb_message.Message):
                _trim_content_fields(v)


def _format(message):
    to_print = copy.deepcopy(message)
    _trim_content_fields(to_print)
    text = text_format.MessageToString(
        to_print, as_one_line=True, use_short_repeated_primitives=True
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


def retry_test(method):
    """
    Decorate a routing function to handle the Retry Test API instructions,
    with method names based on the JSON API.
    """

    def decorator(function):
        @functools.wraps(function)
        def wrapper(self, request, context):
            response_handler = testbench.common.grpc_handle_retry_test_instruction(
                self.db, request, context, method=method
            )
            return response_handler(function(self, request, context))

        return wrapper

    return decorator


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

    @retry_test(method="storage.buckets.delete")
    def DeleteBucket(self, request, context):
        self.db.delete_bucket(
            request.name,
            context=context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return empty_pb2.Empty()

    @retry_test(method="storage.buckets.get")
    def GetBucket(self, request, context):
        bucket = self.db.get_bucket(
            request.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        return bucket.metadata

    @retry_test(method="storage.buckets.insert")
    def CreateBucket(self, request, context):
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.db.insert_bucket(bucket, context)
        return bucket.metadata

    @retry_test(method="storage.buckets.list")
    def ListBuckets(self, request, context):
        if not request.parent.startswith("projects/"):
            return testbench.error.invalid(
                "invalid format for parent=%s" % request.parent, context
            )
        project = request.parent[len("projects/") :]
        prefix = request.prefix

        all_buckets, _ = self.db.list_bucket(project, prefix, None, context)

        unreachable_names = []
        if request.return_partial_success:
            test_id = testbench.common.get_retry_test_id_from_context(context)
            if test_id and self.db.has_instructions_retry_test(
                test_id, "storage.buckets.list", "GRPC"
            ):
                next_instruction = self.db.peek_next_instruction(
                    test_id, "storage.buckets.list"
                )
                match = testbench.common.retry_return_unreachable_buckets.match(
                    next_instruction
                )
                if match:
                    unreachable_names = match.group(1).split(",")
                    self.db.dequeue_next_instruction(test_id, "storage.buckets.list")

            if not unreachable_names:
                unreachable_names = [
                    b.metadata.name
                    for b in all_buckets
                    if "unreachable" in b.metadata.name
                ]

        reachable_buckets = []
        unreachable_buckets = []
        for b in all_buckets:
            if b.metadata.name in unreachable_names:
                unreachable_buckets.append(b.metadata.name)
            else:
                reachable_buckets.append(b)

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

        buckets = [filter(b.metadata) for b in reachable_buckets]
        return storage_pb2.ListBucketsResponse(
            buckets=buckets, unreachable=unreachable_buckets
        )

    @retry_test(method="storage.buckets.lockRetentionPolicy")
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

    @retry_test(method="storage.buckets.getIamPolicy")
    def GetIamPolicy(self, request, context):
        bucket = self.db.get_bucket(request.resource, context)
        return bucket.iam_policy

    @retry_test(method="storage.buckets.setIamPolicy")
    def SetIamPolicy(self, request, context):
        bucket = self.db.get_bucket(request.resource, context)
        bucket.set_iam_policy(request, context)
        return bucket.iam_policy

    @retry_test(method="storage.buckets.testIamPermissions")
    def TestIamPermissions(self, request, context):
        # If the bucket does not exist this will return an error
        _ = self.db.get_bucket(request.resource, context)
        # We do not implement IAM functionality, just echo the request permissions back:
        return iam_policy_pb2.TestIamPermissionsResponse(
            permissions=request.permissions
        )

    @retry_test(method="storage.buckets.patch")
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
        # TODO(#270) - cleanup the manual steps
        safe_paths = set()
        updated_labels = dict()
        removed_label_keys = set()
        replace_labels = False
        for path in request.update_mask.paths:
            if path == "labels":
                replace_labels = True
            elif path.startswith("labels."):
                key = path[len("labels.") :]
                value = request.bucket.labels.get(key, None)
                if value is None:
                    removed_label_keys.add(key)
                else:
                    updated_labels[key] = value
            elif path == "acl" or path == "default_object_acl":
                pass
            else:
                safe_paths.add(path)
        # Build a mask ignoring the manually updated fields
        mask = field_mask_pb2.FieldMask()
        mask.paths[:] = list(safe_paths)
        if not mask.IsValidForDescriptor(storage_pb2.Bucket.DESCRIPTOR):
            return testbench.error.invalid(
                "UpdateBucket() invalid field for Bucket [%s]" % ",".join(mask.paths),
                context,
            )
        bucket = self.db.get_bucket(
            request.bucket.name,
            context,
            preconditions=testbench.common.make_grpc_bucket_preconditions(request),
        )
        mask.MergeMessage(request.bucket, bucket.metadata)
        if "acl" in request.update_mask.paths:
            del bucket.metadata.acl[:]
            bucket.metadata.acl.extend(request.bucket.acl)
        now = datetime.datetime.now()
        if "autoclass" in request.update_mask.paths:
            bucket.metadata.autoclass.toggle_time.FromDatetime(now)
        if "default_object_acl" in request.update_mask.paths:
            del bucket.metadata.default_object_acl[:]
            bucket.metadata.default_object_acl.extend(request.bucket.default_object_acl)
        if replace_labels:
            bucket.metadata.labels.clear()
            bucket.metadata.labels.update(request.bucket.labels)
        else:
            bucket.metadata.labels.update(updated_labels)
            for k in removed_label_keys:
                bucket.metadata.labels.pop(k, None)
        if "soft_delete_policy" in request.update_mask.paths:
            gcs.bucket.Bucket.validate_soft_delete_policy(bucket.metadata, context)
            bucket.metadata.soft_delete_policy.effective_time.FromDatetime(now)
        bucket.metadata.metageneration += 1
        bucket.metadata.update_time.FromDatetime(now)
        return bucket.metadata

    @retry_test(method="storage.objects.compose")
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

            if request.delete_source_objects:
                self.db.delete_object(
                    request.destination.bucket,
                    source.name,
                    generation=source.generation,
                    context=context,
                    preconditions=[precondition],
                )

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

    @retry_test(method="storage.objects.delete")
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

    @retry_test(method="storage.objects.get")
    def GetObject(self, request, context):
        blob = self.db.get_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
            soft_deleted=request.soft_deleted,
        )
        return blob.metadata

    @retry_test(method="storage.objects.get")
    def ReadObject(self, request, context):
        blob = self.db.get_object(
            request.bucket,
            request.object,
            context=context,
            generation=request.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
        )
        meta = blob.metadata
        size = storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES
        start = request.read_offset
        read_end = len(blob.media)
        if start > read_end:
            return testbench.error.range_not_satisfiable(context)
        if request.read_limit > 0:
            read_end = min(read_end, start + request.read_limit)
        content_range = None
        if request.read_offset > 0 or request.read_limit > 0:
            content_range = storage_pb2.ContentRange(
                start=start, end=read_end, complete_length=len(blob.media)
            )

        # Check retry test broken-stream instructions.
        test_id = testbench.common.get_retry_test_id_from_context(context)
        broken_stream_after_bytes = 0
        method = "storage.objects.get"
        if test_id and self.db.has_instructions_retry_test(
            test_id, method, transport="GRPC"
        ):
            next_instruction = self.db.peek_next_instruction(test_id, method)
            broken_stream_after_bytes = testbench.common.get_broken_stream_after_bytes(
                next_instruction
            )

        while start <= read_end:
            end = min(start + size, read_end)
            # Handle retry test broken-stream failures if applicable.
            if broken_stream_after_bytes and end >= broken_stream_after_bytes:
                chunk = blob.media[start:broken_stream_after_bytes]
                yield storage_pb2.ReadObjectResponse(
                    checksummed_data={
                        "content": chunk,
                        "crc32c": crc32c.crc32c(chunk),
                    },
                    metadata=meta,
                    content_range=content_range,
                )
                # Inject broken stream failure and dequeue retry test instructions.
                self.db.dequeue_next_instruction(test_id, method)
                context.abort(
                    grpc.StatusCode.UNAVAILABLE,
                    "Injected 'broken stream' fault",
                )
            chunk = blob.media[start:end]
            yield storage_pb2.ReadObjectResponse(
                checksummed_data={
                    "content": chunk,
                    "crc32c": crc32c.crc32c(chunk),
                },
                metadata=meta,
                content_range=content_range,
            )
            meta = None
            content_range = None
            start = start + size

    @retry_test(method="storage.objects.get")
    def BidiReadObject(self, request_iterator, context):
        # handle first message
        try:
            first_message = next(request_iterator)
        except StopIteration:
            # ok if no messages arrive from the client.
            return

        obj_spec = first_message.read_object_spec
        blob = self.db.get_object(
            obj_spec.bucket,
            obj_spec.object,
            context=context,
            generation=obj_spec.generation,
            preconditions=testbench.common.make_grpc_preconditions(obj_spec),
        )
        metadata = blob.metadata

        # Check retry test broken-stream instructions.
        test_id = testbench.common.get_retry_test_id_from_context(context)
        broken_stream_after_bytes = 0
        method = "storage.objects.get"
        if test_id and self.db.has_instructions_retry_test(
            test_id, method, transport="GRPC"
        ):
            next_instruction = self.db.peek_next_instruction(test_id, method)
            broken_stream_after_bytes = testbench.common.get_broken_stream_after_bytes(
                next_instruction
            )
        return_redirect_token = (
            testbench.common.get_return_read_handle_and_redirect_token(self.db, context)
        )

        # first_response is protected by GIL
        first_response = True

        def response(resp):
            nonlocal first_response
            if first_response:
                first_response = False
                resp.metadata.CopyFrom(metadata)
                resp.read_handle.handle = b"an-opaque-handle"
            # We ignore the read_mask for this test server
            return resp

        if return_redirect_token and len(return_redirect_token):
            detail = any_pb2.Any()
            detail.Pack(
                storage_pb2.BidiReadObjectRedirectedError(
                    routing_token=return_redirect_token
                )
            )
            status_proto = status_pb2.Status(
                code=grpc.StatusCode.ABORTED.value[0],
                message=grpc.StatusCode.ABORTED.value[1],
                details=[detail],
            )
            context.abort_with_status(rpc_status.to_status(status_proto))

        if not first_message.read_ranges:
            # always emit a response to the first request.
            yield response(storage_pb2.BidiReadObjectResponse())

        # In real life requests may be async. For convenience of implementation,
        # we handle each request synchronously before reading the next request.
        def process_read_range(range):
            size = storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES
            # A read range corresponds to a unique read_id.
            # For the same read_id, it is guaranteed that responses are delivered in increasing offset order.
            start = range.read_offset
            read_end = len(blob.media)
            read_id = range.read_id

            if start > read_end or range.read_length < 0:
                status_msg = self._pack_bidiread_error_details(
                    range, grpc.StatusCode.OUT_OF_RANGE
                )
                grpc_status = rpc_status.to_status(status_msg)
                context.abort_with_status(grpc_status)
                return

            if range.read_length > 0:
                read_end = min(read_end, start + range.read_length)

            while True:
                end = min(start + size, read_end)
                # Verify if there are no more bytes to read for the given ReadRange.
                range_end = end == read_end
                chunk = blob.media[start:end]
                read_range = {
                    "read_offset": start,
                    "read_length": end - start,
                    "read_id": read_id,
                }
                yield (chunk, range_end, read_range)
                if start >= read_end:
                    break
                start = end

        # We force all BidiReadObject streams to cancel on the server side after
        # 10 seconds. This is to bound the effect of thread exhaustion on the
        # gRPC server, which can happen when clients don't clean up their
        # streams. Such clients will instead see CANCELLED errors.
        def terminate_w_timer():
            context.cancel()

        timer_thread = Timer(10, terminate_w_timer)
        timer_thread.start()

        returnable = (
            broken_stream_after_bytes if broken_stream_after_bytes else sys.maxsize
        )

        # We don't want to have a thread blocking on request_iterator, so we
        # have to handle results in batches rather than concurrently. This
        # generator yields the read results.
        #
        # We force clients to handle out-of-order responses by selecting one
        # response from each range at a time.
        def responses_for_range_batch(range_batch):
            iters = map(process_read_range, range_batch)
            for responses in itertools.zip_longest(*iters):
                for response in responses:
                    if response is not None:
                        yield response

        def read_results():
            yield from responses_for_range_batch(first_message.read_ranges)
            for request in request_iterator:
                yield from responses_for_range_batch(request.read_ranges)

        for chunk, range_end, read_range in read_results():
            count = len(chunk)
            excess = count - returnable
            if excess > 0:
                chunk = chunk[:returnable]
                range_end = False
                read_range["read_length"] -= excess
            returnable -= count
            yield response(
                storage_pb2.BidiReadObjectResponse(
                    object_data_ranges=[
                        storage_pb2.ObjectRangeData(
                            checksummed_data=storage_pb2.ChecksummedData(
                                content=chunk,
                                crc32c=crc32c.crc32c(chunk),
                            ),
                            read_range=read_range,
                            range_end=range_end,
                        ),
                    ],
                )
            )
            if returnable <= 0:
                self.db.dequeue_next_instruction(test_id, method)
                context.abort(
                    grpc.StatusCode.UNAVAILABLE,
                    "Injected 'broken stream' fault",
                )

    def _to_read_range_error_proto(self, range, status_code):
        return storage_pb2.ReadRangeError(
            read_id=range.read_id,
            status={
                "code": status_code.value[0],
                "message": status_code.value[1],
            },
        )

    def _pack_bidiread_error_details(self, range, status_code):
        range_read_error = self._to_read_range_error_proto(range, status_code)
        code = status_code.value[0]
        message = status_code.value[1]
        detail = any_pb2.Any()
        detail.Pack(
            storage_pb2.BidiReadObjectError(
                read_range_errors=[range_read_error],
            )
        )
        return status_pb2.Status(
            code=code,
            message=message,
            details=[detail],
        )

    @retry_test(method="storage.objects.patch")
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
        # TODO(#270) - cleanup the manual steps
        safe_paths = set()
        updated_metadata = dict()
        removed_metadata_keys = set()
        replace_metadata = False
        updated_contexts = dict()
        removed_contexts_keys = set()
        replace_contexts = False
        reset_contexts = False
        for path in request.update_mask.paths:
            if path == "metadata":
                replace_metadata = True
            elif path.startswith("metadata."):
                key = path[len("metadata.") :]
                value = request.object.metadata.get(key, None)
                if value is None:
                    removed_metadata_keys.add(key)
                else:
                    updated_metadata[key] = value
            elif path == "contexts":
                replace_contexts = True
            elif path == "contexts.custom":
                reset_contexts = True
            elif path.startswith("contexts.custom."):
                key = path[len("contexts.custom.") :]
                value = request.object.contexts.custom.get(key, None)
                if value is None:
                    removed_contexts_keys.add(key)
                else:
                    updated_contexts[key] = value
            elif path == "acl":
                pass
            else:
                safe_paths.add(path)
        # Build a mask ignoring the manually updated fields
        mask = field_mask_pb2.FieldMask()
        mask.paths[:] = list(safe_paths)

        if not mask.IsValidForDescriptor(storage_pb2.Object.DESCRIPTOR):
            return testbench.error.invalid(
                "UpdateObject() invalid field for Object [%s]" % ",".join(mask.paths),
                context,
            )

        acls = None
        if request.predefined_acl:
            acls = testbench.acl.compute_predefined_object_acl(
                request.object.bucket,
                request.object.name,
                request.object.generation,
                request.predefined_acl,
                context,
            )

        def update_impl(blob, live_generation) -> storage_pb2.Object:
            del live_generation
            # TODO(#270) - cleanup the manual steps
            object = blob.metadata
            mask.MergeMessage(request.object, object)
            # Manually replace the repeated fields.
            if "acl" in request.update_mask.paths:
                del object.acl[:]
                object.acl.extend(request.object.acl)
            # Manually handle predefinedACL.
            if request.predefined_acl:
                acls = testbench.acl.compute_predefined_object_acl(
                    request.object.bucket,
                    request.object.name,
                    request.object.generation,
                    request.predefined_acl,
                    context,
                )
                del object.acl[:]
                object.acl.extend(acls)
            if replace_metadata:
                object.metadata.clear()
                object.metadata.update(request.object.metadata)
            else:
                object.metadata.update(updated_metadata)
                for k in removed_metadata_keys:
                    object.metadata.pop(k, None)
            # Manually handle custom contexts due to its complexity.
            curr_time = datetime.datetime.now()
            if reset_contexts:
                object.ClearField("contexts")
            elif replace_contexts:
                object.contexts.custom.clear()
                for k, v in request.object.contexts.custom.items():
                    dest_payload = object.contexts.custom[k]
                    dest_payload.CopyFrom(v)
                    dest_payload.create_time.FromDatetime(curr_time)
                    dest_payload.update_time.FromDatetime(curr_time)
            else:
                for k, v in updated_contexts.items():
                    if k not in object.contexts.custom:
                        # This is a brand new key, add create and update time.
                        updated_contexts[k].create_time.FromDatetime(curr_time)
                        updated_contexts[k].update_time.FromDatetime(curr_time)
                    elif v.value != object.contexts.custom[k].value:
                        # This is an existing key, copy original key's create
                        # time and add new update time.
                        updated_contexts[k].create_time.CopyFrom(
                            object.contexts.custom[k].create_time
                        )
                        updated_contexts[k].update_time.FromDatetime(curr_time)
                    object.contexts.custom[k].CopyFrom(v)
                for k in removed_contexts_keys:
                    object.contexts.custom.pop(k, None)
            object.metageneration += 1
            object.update_time.FromDatetime(curr_time)
            return object

        self.db.insert_test_bucket()

        return self.db.do_update_object(
            request.object.bucket,
            request.object.name,
            context=context,
            generation=request.object.generation,
            preconditions=testbench.common.make_grpc_preconditions(request),
            update_fn=update_impl,
        )

    def __get_bucket(self, bucket_name, context) -> storage_pb2.Bucket:
        return self.db.get_bucket(bucket_name, context).metadata

    @retry_test(method="storage.objects.restore")
    def RestoreObject(self, request, context):
        preconditions = testbench.common.make_grpc_preconditions(request)
        blob = self.db.restore_object(
            request.bucket, request.object, request.generation, preconditions, context
        )
        return blob.metadata

    # The MoveObject gRPC call only performas a copy + delete of a single object
    # as testbench does not have the concept of folders.
    # This will suffice for a very basic test but lacks the full depth of the production API.
    def MoveObject(self, request, context):
        preconditions = testbench.common.make_grpc_preconditions(request)
        bucket = self.db.get_bucket(request.bucket, context).metadata
        src_object = self.db.get_object(
            request.bucket,
            request.source_object,
            preconditions=preconditions,
            context=context,
        )
        dst_metadata = storage_pb2.Object()
        dst_metadata.CopyFrom(src_object.metadata)
        dst_metadata.bucket = request.bucket
        dst_metadata.name = request.destination_object
        dst_media = b""
        dst_media += src_object.media
        dst_object, _ = gcs.object.Object.init(
            request, dst_metadata, dst_media, bucket, False, context, csek=False
        )
        self.db.insert_object(
            request.bucket,
            dst_object,
            context=context,
            preconditions=preconditions,
        )
        self.db.delete_object(
            request.bucket,
            request.source_object,
            context=context,
            preconditions=preconditions,
        )

        return dst_object.metadata

    @retry_test(method="storage.objects.insert")
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

    @retry_test(method="storage.objects.insert")
    def BidiWriteObject(self, request_iterator, context):
        expected_redirect_token = testbench.common.get_expect_redirect_token(
            self.db, context
        )
        if expected_redirect_token:
            request_params = testbench.common.get_context_request_params(context)
            if (
                request_params
                and f"routing_token={expected_redirect_token}" in request_params
            ):
                test_id = testbench.common.get_retry_test_id_from_context(context)
                self.db.dequeue_next_instruction(test_id, "storage.objects.insert")

        return gcs.upload.Upload.process_bidi_write_object_grpc(
            self.db, request_iterator, context
        )

    @retry_test(method="storage.objects.list")
    def ListObjects(self, request, context):
        items, prefixes = self.db.list_object(request, request.parent, context)
        return storage_pb2.ListObjectsResponse(objects=items, prefixes=prefixes)

    @retry_test(method="storage.objects.rewrite")
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

    @retry_test(method="storage.objects.insert")
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


def run(port, database, echo_metadata=False):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    storage_pb2_grpc.add_StorageServicer_to_server(
        StorageServicer(database, echo_metadata), server
    )
    port = server.add_insecure_port("0.0.0.0:%d" % port)
    server.start()
    return port, server
