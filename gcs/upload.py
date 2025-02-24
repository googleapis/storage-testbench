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

"""Helper class to hold data during an upload."""

import datetime
import hashlib
import itertools
import json
import types
import uuid

import crc32c
import flask
import google.protobuf.any_pb2 as any_pb2
import grpc
from google.protobuf import json_format
from google.rpc import status_pb2
from grpc_status import rpc_status

import gcs
import testbench
from google.storage.v2 import storage_pb2


class Upload(types.SimpleNamespace):
    """Holds data during an upload.

    An upload may require multiple RPCs, or at least a long streaming RPC. We
    need an object to hold the data during the upload. Note that in the case
    of resumable uploads the metadata for the object, and any pre-conditions,
    are provided at the start of the upload, but are used when the upload
    completes.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def init(cls, request, metadata, bucket, location, upload_id):
        return cls(
            request=request,
            metadata=metadata,
            bucket=bucket,
            location=location,
            upload_id=upload_id,
            media=b"",
            complete=False,
            transfer=set(),
        )

    @classmethod
    def __preprocess_rest_metadata(cls, metadata):
        return testbench.common.preprocess_object_metadata(metadata)

    @classmethod
    def __create_upload_id(cls, bucket_name, object_name):
        return hashlib.sha256(
            ("%s/%s/o/%s" % (uuid.uuid4().hex, bucket_name, object_name)).encode(
                "utf-8"
            )
        ).hexdigest()

    @classmethod
    def init_resumable_rest(cls, request, bucket):
        query_name = request.args.get("name", None)
        metadata = storage_pb2.Object()
        if len(request.data) > 0:
            data = json.loads(request.data)
            data_name = data.get("name", None)
            if (
                query_name is not None
                and data_name is not None
                and query_name != data_name
            ):
                testbench.error.invalid(
                    "Value '%s' in content does not agree with value '%s'."
                    % (data_name, query_name),
                    context=None,
                )
            metadata = json_format.ParseDict(
                cls.__preprocess_rest_metadata(data), metadata
            )
            # Add some annotations to make it easier to write tests
            metadata.metadata["x_emulator_upload"] = "resumable"
            if data.get("crc32c", None) is not None:
                metadata.metadata["x_emulator_crc32c"] = data.get("crc32c")
            if data.get("md5Hash", None) is not None:
                metadata.metadata["x_emulator_md5"] = data.get("md5Hash")
        if metadata.metadata.get("x_emulator_crc32c", None) is None:
            metadata.metadata["x_emulator_no_crc32c"] = "true"
        if metadata.metadata.get("x_emulator_md5", None) is None:
            metadata.metadata["x_emulator_no_md5"] = "true"
        if query_name:
            metadata.name = query_name
        if metadata.name == "":
            testbench.error.invalid("No object name", context=None)
        if metadata.content_type == "":
            metadata.content_type = request.headers.get(
                "x-upload-content-type", "application/octet-stream"
            )
        upload_id = cls.__create_upload_id(bucket.name, metadata.name)
        location = (
            request.host_url
            + "upload/storage/v1/b/%s/o?uploadType=resumable&upload_id=%s"
            % (bucket.bucket_id, upload_id)
        )
        headers = {
            key.lower(): value
            for key, value in request.headers.items()
            if key.lower().startswith("x-")
        }
        request = testbench.common.FakeRequest(
            args=request.args.to_dict(), headers=headers, data=b""
        )
        upload = cls.init(request, metadata, bucket, location, upload_id)
        upload.preconditions = testbench.common.make_json_preconditions(request)
        return upload

    @classmethod
    def init_resumable_grpc(
        cls,
        request: storage_pb2.StartResumableWriteRequest,
        bucket: storage_pb2.Bucket,
        context,
    ):
        metadata = request.write_object_spec.resource
        metadata.metadata["x_emulator_upload"] = "resumable"
        upload_id = cls.__create_upload_id(bucket.name, metadata.name)
        fake_request = testbench.common.FakeRequest.init_protobuf(
            request.write_object_spec, context
        )
        fake_request.update_protobuf(request.write_object_spec, context)
        upload = cls.init(fake_request, metadata, bucket, "", upload_id)
        upload.preconditions = testbench.common.make_grpc_preconditions(
            request.write_object_spec
        )
        return upload

    @classmethod
    def __init_first_write_grpc(
        cls,
        request: storage_pb2.WriteObjectRequest,
        bucket: storage_pb2.Bucket,
        context,
    ):
        metadata = request.write_object_spec.resource
        metadata.metadata["x_emulator_upload"] = "grpc"
        upload_id = cls.__create_upload_id(bucket.name, metadata.name)
        fake_request = testbench.common.FakeRequest.init_protobuf(request, context)
        fake_request.update_protobuf(request.write_object_spec, context)
        upload = cls.init(fake_request, metadata, bucket, "", upload_id)
        upload.preconditions = testbench.common.make_grpc_preconditions(
            request.write_object_spec
        )
        return upload

    @classmethod
    def init_write_object_grpc(cls, db, request_iterator, context):
        """Process an WriteObject streaming RPC, returning the upload object associated with it."""
        upload, object_checksums, is_resumable = None, None, False
        for request in request_iterator:
            first_message = request.WhichOneof("first_message")
            if first_message == "upload_id":
                upload = db.get_upload(request.upload_id, context)
                if upload.complete:
                    testbench.error.invalid(
                        "Uploading to a completed upload %s" % upload.upload_id, context
                    )
                    return None, False
                is_resumable = True
            elif first_message == "write_object_spec":
                bucket = db.get_bucket(
                    request.write_object_spec.resource.bucket, context
                ).metadata
                upload = cls.__init_first_write_grpc(request, bucket, context)
            elif upload is None:
                testbench.error.invalid("Upload missing a first_message field", context)
                return None, False

            if request.HasField("object_checksums"):
                # The object checksums may appear only in the first message *or* the last message, but not both
                if first_message is None and request.finish_write == False:
                    testbench.error.invalid(
                        "Object checksums can be included only in the first or last message",
                        context,
                    )
                    return None, False
                if object_checksums is not None:
                    testbench.error.invalid(
                        "Duplicate object checksums in upload",
                        context,
                    )
                    return None, False
                object_checksums = request.object_checksums

            data = request.WhichOneof("data")
            if data == "checksummed_data":
                checksummed_data = request.checksummed_data
            elif data is None and request.finish_write:
                # Handles final message with no data to insert.
                upload.complete = True
                continue
            else:
                testbench.error.invalid("Invalid data field in upload", context)
                return None, False

            content = checksummed_data.content
            crc32c_hash = (
                checksummed_data.crc32c if checksummed_data.HasField("crc32c") else None
            )
            if crc32c_hash is not None:
                actual_crc32c = crc32c.crc32c(content)
                if actual_crc32c != crc32c_hash:
                    testbench.error.mismatch(
                        "crc32c in checksummed data",
                        crc32c_hash,
                        actual_crc32c,
                        context,
                    )
                    return None, False

            # Handle retry test return-X-after-YK failures if applicable.
            (
                rest_code,
                after_bytes,
                test_id,
            ) = testbench.common.get_retry_uploads_error_after_bytes(
                db, request, context=context, transport="GRPC"
            )
            expected_persisted_size = request.write_offset + len(content)
            if rest_code:
                testbench.common.handle_grpc_retry_uploads_error_after_bytes(
                    context,
                    upload,
                    content,
                    db,
                    rest_code,
                    after_bytes,
                    write_offset=request.write_offset,
                    persisted_size=len(upload.media),
                    expected_persisted_size=expected_persisted_size,
                    test_id=test_id,
                )

            # The testbench should ignore any request bytes that have already been persisted,
            # thus we validate write_offset against persisted_size.
            # https://github.com/googleapis/googleapis/blob/15b48f9ed0ae8b034e753c6895eb045f436e257c/google/storage/v2/storage.proto#L320-L329
            if request.write_offset < len(upload.media):
                range_start = len(upload.media) - request.write_offset
                content = testbench.common.partial_media(
                    content, range_end=len(content), range_start=range_start
                )

            upload.media += content
            if request.finish_write:
                upload.complete = True

        if upload is None:
            testbench.error.invalid("Upload missing a first_message field", context)
            return None, False
        if object_checksums is None:
            upload.metadata.metadata["x_emulator_no_crc32c"] = "true"
            upload.metadata.metadata["x_emulator_no_md5"] = "true"
            return upload, is_resumable
        if object_checksums.HasField("crc32c"):
            upload.metadata.metadata[
                "x_emulator_crc32c"
            ] = testbench.common.rest_crc32c_from_proto(object_checksums.crc32c)
        else:
            upload.metadata.metadata["x_emulator_no_crc32c"] = "true"
        if object_checksums.md5_hash is not None and object_checksums.md5_hash != b"":
            upload.metadata.metadata[
                "x_emulator_md5"
            ] = testbench.common.rest_md5_from_proto(object_checksums.md5_hash)
        else:
            upload.metadata.metadata["x_emulator_no_md5"] = "true"
        return upload, is_resumable

    @classmethod
    def _insert_empty_appendable_object(cls, db, upload, spec, context):
        # Construct the appendable object unfinalized in metadata. The upload
        # will reflect the insertion-time generation.
        blob, _ = gcs.object.Object.init(
            upload.request,
            upload.metadata,
            upload.media,
            upload.bucket,
            False,
            context,
            finalize=False,
        )

        def insert_if_latest_is_unfinalized(latest_blob, live_generation):
            if latest_blob is not None and not latest_blob.metadata.HasField(
                "finalize_time"
            ):
                # The live generation exists but is unfinalized, return an
                # error. This is slightly different behavior from the real
                # implementation, but it is sufficient for testing.
                context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    "Attempting to overwrite an unfinalized object",
                )
            db.insert_object(
                upload.bucket.name,
                blob,
                context=context,
                preconditions=upload.preconditions,
            )
            return blob

        return db.do_update_object(
            upload.bucket.name,
            blob.metadata.name,
            update_fn=insert_if_latest_is_unfinalized,
            context=context,
            preconditions=upload.preconditions,
            require_live_current_generation=False,
        )

    @classmethod
    def process_bidi_write_object_grpc(cls, db, request_iterator, context):
        """Process a BidiWriteObject streaming RPC, and yield a stream of responses."""
        # Many tests use a list as the request_iterator
        request_iterator = iter(request_iterator)
        upload, object_checksums, is_resumable, is_appendable = None, None, False, False
        appendable_metadata_in_first_response = False
        try:
            first_msg = next(request_iterator)
        except StopIteration:
            # At least one message is required. This function raises.
            testbench.error.invalid("Missing BidiWriteObjectRequest", context)

        write_type = first_msg.WhichOneof("first_message")
        if write_type == "upload_id":  # resumable upload
            upload = db.get_upload(first_msg.upload_id, context)
            if upload.complete:
                # Resuming an already finalized object will result with a response
                # containing the uploaded object's metadata.
                yield storage_pb2.BidiWriteObjectResponse(resource=upload.blob.metadata)
                return
            is_resumable = True
        elif write_type == "write_object_spec":  # new object
            bucket = db.get_bucket(
                first_msg.write_object_spec.resource.bucket, context
            ).metadata
            upload = cls.__init_first_write_grpc(first_msg, bucket, context)
            if first_msg.write_object_spec.appendable:
                is_appendable = True
                appendable_metadata_in_first_response = True
                blob = cls._insert_empty_appendable_object(
                    db, upload, first_msg.write_object_spec, context
                )
                upload.blob = blob
                db.insert_upload(upload)
        elif write_type == "append_object_spec":
            is_appendable = True
            upload = db.get_upload(
                first_msg.append_object_spec.write_handle.handle.decode("utf-8"),
                context,
            )
            preconditions = testbench.common.make_grpc_preconditions(
                first_msg.append_object_spec
            )
            blob = db.get_object(
                first_msg.append_object_spec.bucket,
                first_msg.append_object_spec.object,
                context=context,
                generation=first_msg.append_object_spec.generation,
                preconditions=preconditions,
            )
            if blob.metadata.HasField("finalize_time"):
                context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    "Attempting to append to already-finalized object",
                )
        else:
            testbench.error.invalid("Upload missing a first_message field", context)

        if first_msg.HasField("object_checksums"):
            object_checksums = first_msg.object_checksums

        return_redirect_token = (
            testbench.common.get_return_write_handle_and_redirect_token(db, context)
        )
        if return_redirect_token:
            err = storage_pb2.BidiWriteObjectRedirectedError()
            err.generation = upload.metadata.generation
            err.write_handle.handle = bytes(upload.upload_id, "utf-8")
            err.routing_token = return_redirect_token
            detail = any_pb2.Any()
            detail.Pack(err)
            status_proto = status_pb2.Status(
                code=grpc.StatusCode.ABORTED.value[0],
                message=grpc.StatusCode.ABORTED.value[1],
                details=[detail],
            )
            context.abort_with_status(rpc_status.to_status(status_proto))

        # Treat the rest of the first message as a data request, then keep
        # pulling from request_iterator
        first_msg.ClearField("first_message")
        first_msg.ClearField("object_checksums")
        request_iterator = itertools.chain([first_msg], request_iterator)

        first_response = True

        def response(msg):
            nonlocal first_response
            if first_response:
                first_response = False
                if is_appendable and appendable_metadata_in_first_response:
                    # For simplicity in the testbench implementation, just use
                    # the database's upload_id as the appendable handle.
                    msg.write_handle.handle = bytes(upload.upload_id, "utf-8")
                    # Appendable objects also exist at creation time. That's not
                    # fully supported in the testbench, but we can at least
                    # return the object metadata.
                    obj_len = msg.persisted_size
                    msg.resource.CopyFrom(upload.metadata)
                    msg.resource.size = obj_len
            return msg

        for request in request_iterator:
            if request.HasField("first_message"):
                testbench.error.invalid("Multiple first_message", context)

            if request.HasField("object_checksums"):
                # The object checksums may appear only in the first message *or* the last message, but not both
                if not request.finish_write:
                    testbench.error.invalid(
                        "Object checksums can be included only in the first or last message",
                        context,
                    )
                if object_checksums is not None:
                    testbench.error.invalid(
                        "Duplicate object checksums in upload",
                        context,
                    )
                object_checksums = request.object_checksums

            data = request.WhichOneof("data")
            if data == "checksummed_data":
                checksummed_data = request.checksummed_data
                content = checksummed_data.content
                crc32c_hash = (
                    checksummed_data.crc32c
                    if checksummed_data.HasField("crc32c")
                    else None
                )
                if crc32c_hash is not None:
                    actual_crc32c = crc32c.crc32c(content)
                    if actual_crc32c != crc32c_hash:
                        testbench.error.mismatch(
                            "crc32c in checksummed data",
                            crc32c_hash,
                            actual_crc32c,
                            context,
                        )

                # Handle retry test return-X-after-YK failures if applicable.
                (
                    rest_code,
                    after_bytes,
                    test_id,
                ) = testbench.common.get_retry_uploads_error_after_bytes(
                    db, request, context=context, transport="GRPC"
                )
                expected_persisted_size = request.write_offset + len(content)
                if rest_code:
                    testbench.common.handle_grpc_retry_uploads_error_after_bytes(
                        context,
                        upload,
                        content,
                        db,
                        rest_code,
                        after_bytes,
                        write_offset=request.write_offset,
                        persisted_size=len(upload.media),
                        expected_persisted_size=expected_persisted_size,
                        test_id=test_id,
                    )

                # The testbench should ignore any request bytes that have already been persisted,
                # thus we validate write_offset against persisted_size.
                # https://github.com/googleapis/googleapis/blob/15b48f9ed0ae8b034e753c6895eb045f436e257c/google/storage/v2/storage.proto#L320-L329
                if request.write_offset < len(upload.media):
                    range_start = len(upload.media) - request.write_offset
                    content = testbench.common.partial_media(
                        content, range_end=len(content), range_start=range_start
                    )
                # Currently, the testbench will always checkpoint and flush data for testing purposes,
                # instead of the 15 seconds interval used in the GCS server.
                # TODO(#592): Refactor testbench checkpointing to more closely follow GCS server behavior.
                upload.media += content
            elif data is not None:
                testbench.error.invalid("Invalid data field in upload", context)

            if request.finish_write:
                upload.complete = True
                break
            elif request.state_lookup:
                # For uploads not yet completed, yield response with persisted_size.
                # For uploads that are complete, finalize the upload outside the request loop by
                # storing full object checksums, creating new object, and yielding response with
                # object metadata.
                yield response(
                    storage_pb2.BidiWriteObjectResponse(
                        persisted_size=len(upload.media)
                    )
                )

        if object_checksums is None:
            upload.metadata.metadata["x_emulator_no_crc32c"] = "true"
            upload.metadata.metadata["x_emulator_no_md5"] = "true"
        else:
            if object_checksums.HasField("crc32c"):
                upload.metadata.metadata[
                    "x_emulator_crc32c"
                ] = testbench.common.rest_crc32c_from_proto(object_checksums.crc32c)
            else:
                upload.metadata.metadata["x_emulator_no_crc32c"] = "true"
            if (
                object_checksums.md5_hash is not None
                and object_checksums.md5_hash != b""
            ):
                upload.metadata.metadata[
                    "x_emulator_md5"
                ] = testbench.common.rest_md5_from_proto(object_checksums.md5_hash)
            else:
                upload.metadata.metadata["x_emulator_no_md5"] = "true"

        # Create a new object when the write is completed.
        if upload.complete:
            if is_appendable:

                def finalize_blob(blob, unused_generation):
                    blob.media = upload.media
                    blob.metadata.finalize_time.FromDatetime(
                        datetime.datetime.now(datetime.timezone.utc)
                    )
                    blob.metadata.size = len(upload.media)
                    return blob

                blob = db.do_update_object(
                    upload.bucket.name,
                    upload.metadata.name,
                    update_fn=finalize_blob,
                    context=context,
                    generation=upload.metadata.generation,
                )
            else:
                blob, _ = gcs.object.Object.init(
                    upload.request,
                    upload.metadata,
                    upload.media,
                    upload.bucket,
                    False,
                    context,
                )
                upload.blob = blob
                db.insert_object(
                    upload.bucket.name,
                    blob,
                    context=context,
                    preconditions=upload.preconditions,
                )
            yield response(storage_pb2.BidiWriteObjectResponse(resource=blob.metadata))
        elif not is_resumable and not is_appendable:
            testbench.error.missing("finish_write in request", context)

    def resumable_status_rest(self, override_308=False):
        response = flask.make_response()
        if len(self.media) > 1 and not self.complete:
            response.headers["Range"] = "bytes=0-%d" % (len(self.media) - 1)
        response.status_code = 308

        if override_308:
            response.headers["X-Http-Status-Code-Override"] = "308"
            response.status_code = 200
        return response
