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

import hashlib
import json
import types
import uuid

import crc32c
import flask
from google.protobuf import json_format

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
        upload.preconditions = testbench.common.make_grpc_preconditions(request)
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
            else:
                print("WARNING unexpected data field %s\n" % data)
                continue
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
            upload.media += checksummed_data.content
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

    def resumable_status_rest(self, override_308=False):
        response = flask.make_response()
        if len(self.media) > 1 and not self.complete:
            response.headers["Range"] = "bytes=0-%d" % (len(self.media) - 1)
        response.status_code = 308

        if override_308:
            response.headers["X-Http-Status-Code-Override"] = "308"
            response.status_code = 200
        return response
