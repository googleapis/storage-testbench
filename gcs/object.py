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

"""Implement a class to simulate GCS object."""

import base64
import datetime
import hashlib

import crc32c
import testbench

from google.cloud.storage_v1.proto import storage_resources_pb2 as resources_pb2
from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums
from google.protobuf import json_format


class Object:
    modifiable_fields = [
        "content_encoding",
        "content_disposition",
        "cache_control",
        "acl",
        "content_language",
        "content_type",
        "storage_class",
        "kms_key_name",
        "temporary_hold",
        "retention_expiration_time",
        "metadata",
        "event_based_hold",
        "customer_encryption",
    ]

    rest_only_fields = ["customTime"]

    def __init__(self, metadata, media, bucket, rest_only=None):
        self.metadata = metadata
        self.media = media
        self.bucket = bucket
        self.rest_only = rest_only

    @classmethod
    def __extract_rest_only(cls, data):
        rest_only = {}
        for field in Object.rest_only_fields:
            if field in data:
                rest_only[field] = data.pop(field)
        return rest_only

    @classmethod
    def __insert_predefined_acl(cls, metadata, bucket, predefined_acl, context):
        if (
            predefined_acl == ""
            or predefined_acl
            == CommonEnums.PredefinedObjectAcl.PREDEFINED_OBJECT_ACL_UNSPECIFIED
        ):
            return
        if bucket.iam_configuration.uniform_bucket_level_access.enabled:
            testbench.error.invalid(
                "Predefined ACL with uniform bucket level access enabled", context
            )
        acls = testbench.acl.compute_predefined_object_acl(
            metadata.bucket, metadata.name, metadata.generation, predefined_acl, context
        )
        del metadata.acl[:]
        metadata.acl.extend(acls)

    @classmethod
    def __enrich_acl(cls, metadata):
        for entry in metadata.acl:
            entry.bucket = metadata.bucket
            entry.object = metadata.name
            entry.generation = metadata.generation

    # TODO(#4893): Remove `rest_only`
    @classmethod
    def init(
        cls, request, metadata, media, bucket, is_destination, context, rest_only=None
    ):
        instruction = testbench.common.extract_instruction(request, context)
        if instruction == "inject-upload-data-error":
            media = testbench.common.corrupt_media(media)
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        metadata.bucket = bucket.name
        metadata.generation = int(timestamp.timestamp() * 1000)
        metadata.metageneration = 1
        metadata.id = "%s/o/%s#%d" % (
            metadata.bucket,
            metadata.name,
            metadata.generation,
        )
        metadata.size = len(media)
        actual_md5Hash = base64.b64encode(hashlib.md5(media).digest()).decode("utf-8")
        if metadata.md5_hash != "" and actual_md5Hash != metadata.md5_hash:
            testbench.error.mismatch(
                "md5Hash", metadata.md5_hash, actual_md5Hash, context
            )
        actual_crc32c = crc32c.crc32c(media)
        if metadata.HasField("crc32c") and actual_crc32c != metadata.crc32c.value:
            testbench.error.mismatch(
                "crc32c", metadata.crc32c.value, actual_crc32c, context
            )
        metadata.md5_hash = actual_md5Hash
        metadata.crc32c.value = actual_crc32c
        metadata.time_created.FromDatetime(timestamp)
        metadata.updated.FromDatetime(timestamp)
        metadata.owner.entity = testbench.acl.get_object_entity("OWNER", context)
        metadata.owner.entity_id = hashlib.md5(
            metadata.owner.entity.encode("utf-8")
        ).hexdigest()
        algorithm, key_b64, key_sha256_b64 = testbench.csek.extract(
            request, False, context
        )
        if algorithm != "":
            testbench.csek.check(algorithm, key_b64, key_sha256_b64, context)
            metadata.customer_encryption.encryption_algorithm = algorithm
            metadata.customer_encryption.key_sha256 = key_sha256_b64
        default_projection = CommonEnums.Projection.NO_ACL
        is_uniform = bucket.iam_configuration.uniform_bucket_level_access.enabled
        # TODO(#..) - this is probably a bug, cleanup once we move all the code
        bucket.iam_configuration.uniform_bucket_level_access.enabled = False
        if len(metadata.acl) != 0:
            default_projection = CommonEnums.Projection.FULL
        else:
            predefined_acl = testbench.acl.extract_predefined_acl(
                request, is_destination, context
            )
            if (
                predefined_acl
                == CommonEnums.PredefinedObjectAcl.PREDEFINED_OBJECT_ACL_UNSPECIFIED
            ):
                predefined_acl = (
                    CommonEnums.PredefinedObjectAcl.OBJECT_ACL_PROJECT_PRIVATE
                )
            elif predefined_acl == "":
                predefined_acl = "projectPrivate"
            elif is_uniform:
                testbench.error.invalid(
                    "Predefined ACL with uniform bucket level access enabled", context
                )
            cls.__insert_predefined_acl(metadata, bucket, predefined_acl, context)
        cls.__enrich_acl(metadata)
        bucket.iam_configuration.uniform_bucket_level_access.enabled = is_uniform
        if rest_only is None:
            rest_only = {}
        return (
            cls(metadata, media, bucket, rest_only),
            testbench.common.extract_projection(request, default_projection, context),
        )

    @classmethod
    def init_dict(cls, request, metadata, media, bucket, is_destination):
        rest_only = cls.__extract_rest_only(metadata)
        metadata = json_format.ParseDict(metadata, resources_pb2.Object())
        return cls.init(
            request, metadata, media, bucket, is_destination, None, rest_only
        )

    @classmethod
    def init_media(cls, request, bucket):
        object_name = request.args.get("name", None)
        media = testbench.common.extract_media(request)
        if object_name is None:
            testbench.error.missing("name", None)
        metadata = {
            "bucket": bucket.name,
            "name": object_name,
            "metadata": {"x_emulator_upload": "simple"},
        }
        return cls.init_dict(request, metadata, media, bucket, False)

    @classmethod
    def init_multipart(cls, request, bucket):
        metadata, media_headers, media = testbench.common.parse_multipart(request)
        metadata["name"] = request.args.get("name", metadata.get("name", None))
        if metadata["name"] is None:
            testbench.error.missing("name", None)
        if (
            metadata.get("contentType") is not None
            and media_headers.get("content-type") is not None
            and metadata.get("contentType") != media_headers.get("content-type")
        ):
            testbench.error.mismatch(
                "Content-Type",
                media_headers.get("content-type"),
                metadata.get("contentType"),
                None,
            )
        metadata["bucket"] = bucket.name
        if "contentType" not in metadata:
            metadata["contentType"] = media_headers.get("content-type")
        metadata["metadata"] = (
            {} if "metadata" not in metadata else metadata["metadata"]
        )
        metadata["metadata"]["x_emulator_upload"] = "multipart"
        if "md5Hash" in metadata:
            metadata["metadata"]["x_emulator_md5"] = metadata["md5Hash"]
            metadata["md5Hash"] = metadata["md5Hash"]
        if "crc32c" in metadata:
            metadata["metadata"]["x_emulator_crc32c"] = metadata["crc32c"]
            metadata["crc32c"] = testbench.common.rest_crc32c_to_proto(
                metadata["crc32c"]
            )
        return cls.init_dict(request, metadata, media, bucket, False)

    @classmethod
    def init_xml(cls, request, bucket, name):
        media = testbench.common.extract_media(request)
        metadata = {
            "bucket": bucket.name,
            "name": name,
            "metadata": {"x_emulator_upload": "xml"},
        }
        if "content-type" in request.headers:
            metadata["contentType"] = request.headers["content-type"]
        fake_request = testbench.common.FakeRequest.init_xml(request)
        x_goog_hash = fake_request.headers.get("x-goog-hash")
        if x_goog_hash is not None:
            for checksum in x_goog_hash.split(","):
                if checksum.startswith("md5="):
                    md5Hash = checksum[4:]
                    metadata["md5Hash"] = md5Hash
                if checksum.startswith("crc32c="):
                    crc32c_value = checksum[7:]
                    metadata["crc32c"] = testbench.common.rest_crc32c_to_proto(
                        crc32c_value
                    )
        blob, _ = cls.init_dict(fake_request, metadata, media, bucket, False)
        return blob, fake_request

    # === RESPONSE === #

    @classmethod
    def rest(cls, metadata, rest_only):
        response = json_format.MessageToDict(metadata)
        response["kind"] = "storage#object"
        response["crc32c"] = testbench.common.rest_crc32c_from_proto(response["crc32c"])
        response.update(rest_only)
        old_metadata = {}
        if "metadata" in response:
            for key, value in response["metadata"].items():
                if "emulator" in key:
                    old_key = key.replace("emulator", "testbench")
                    old_metadata[old_key] = value
            response["metadata"].update(old_metadata)
        if "acl" in response:
            for entry in response["acl"]:
                entry["kind"] = "storage#objectAccessControl"
        return response

    def rest_metadata(self):
        return self.rest(self.metadata, self.rest_only)
