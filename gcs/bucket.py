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

"""Implement a class to simulate GCS buckets."""

import datetime
import hashlib
import json
import re
import scalpl

from google.cloud.storage_v1.proto import storage_resources_pb2 as resources_pb2
from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums
from google.iam.v1 import policy_pb2
from google.protobuf import json_format

import testbench


class Bucket:
    rest_only_fields = ["iamConfiguration.publicAccessPrevention"]

    def __init__(self, metadata, notifications, iam_policy, rest_only):
        self.metadata = metadata
        self.notifications = notifications
        self.iam_policy = iam_policy
        self.rest_only = rest_only

    @classmethod
    def __validate_bucket_name(cls, bucket_name, context):
        valid = True
        if "." in bucket_name:
            valid &= len(bucket_name) <= 222
            valid &= all([len(part) <= 63 for part in bucket_name.split(".")])
        else:
            valid &= len(bucket_name) <= 63
            valid &= (
                re.match("^[a-z0-9][a-z0-9._\\-]+[a-z0-9]$", bucket_name) is not None
            )
            valid &= not bucket_name.startswith("goog")
            valid &= re.search("g[0o][0o]g[1l][e3]", bucket_name) is None
        if not valid:
            testbench.error.invalid("Bucket name %s" % bucket_name, context)

    @classmethod
    def __preprocess_rest(cls, data):
        proxy = scalpl.Cut(data)
        keys = testbench.common.nested_key(data)
        proxy.pop("iamConfiguration.bucketPolicyOnly", False)
        for key in keys:
            if key.endswith("createdBefore"):
                proxy[key] = proxy[key] + "T00:00:00Z"
        rest_only = {}
        for field in Bucket.rest_only_fields:
            if field in proxy:
                rest_only[field] = proxy.pop(field)
        return proxy.data, rest_only

    @classmethod
    def __insert_predefined_acl(cls, metadata, predefined_acl, context):
        if (
            predefined_acl == ""
            or predefined_acl
            == CommonEnums.PredefinedBucketAcl.PREDEFINED_BUCKET_ACL_UNSPECIFIED
        ):
            return
        if metadata.iam_configuration.uniform_bucket_level_access.enabled:
            testbench.error.invalid(
                "Predefined ACL with uniform bucket level access enabled", context
            )
        acls = testbench.acl.compute_predefined_bucket_acl(
            metadata.name, predefined_acl, context
        )
        del metadata.acl[:]
        metadata.acl.extend(acls)

    @classmethod
    def __insert_predefined_default_object_acl(
        cls, metadata, predefined_default_object_acl, context
    ):
        if (
            predefined_default_object_acl == ""
            or predefined_default_object_acl
            == CommonEnums.PredefinedObjectAcl.PREDEFINED_OBJECT_ACL_UNSPECIFIED
        ):
            return
        if metadata.iam_configuration.uniform_bucket_level_access.enabled:
            testbench.error.invalid(
                "Predefined Default Object ACL with uniform bucket level access enabled",
                context,
            )
        acls = testbench.acl.compute_predefined_default_object_acl(
            metadata.name, predefined_default_object_acl, context
        )
        del metadata.default_object_acl[:]
        metadata.default_object_acl.extend(acls)

    @classmethod
    def __enrich_acl(cls, metadata):
        for entry in metadata.acl:
            entry.bucket = metadata.name
        for entry in metadata.default_object_acl:
            entry.bucket = metadata.name

    # === INITIALIZATION === #

    @classmethod
    def init(cls, request, context, rest_only=None):
        time_created = datetime.datetime.now()
        metadata = None
        if context is not None:
            metadata = request.bucket
        else:
            metadata, rest_only = cls.__preprocess_rest(json.loads(request.data))
            metadata = json_format.ParseDict(metadata, resources_pb2.Bucket())
        cls.__validate_bucket_name(metadata.name, context)
        default_projection = CommonEnums.Projection.NO_ACL
        if len(metadata.acl) != 0 or len(metadata.default_object_acl) != 0:
            default_projection = CommonEnums.Projection.FULL
        is_uniform = metadata.iam_configuration.uniform_bucket_level_access.enabled
        metadata.iam_configuration.uniform_bucket_level_access.enabled = False
        if len(metadata.acl) == 0:
            predefined_acl = testbench.acl.extract_predefined_acl(
                request, False, context
            )
            if (
                predefined_acl
                == CommonEnums.PredefinedBucketAcl.PREDEFINED_BUCKET_ACL_UNSPECIFIED
            ):
                predefined_acl = (
                    CommonEnums.PredefinedBucketAcl.BUCKET_ACL_PROJECT_PRIVATE
                )
            elif predefined_acl == "":
                predefined_acl = "projectPrivate"
            elif is_uniform:
                testbench.error.invalid(
                    "Predefined ACL with uniform bucket level access enabled", context
                )
            cls.__insert_predefined_acl(metadata, predefined_acl, context)
        if len(metadata.default_object_acl) == 0:
            predefined_default_object_acl = (
                testbench.acl.extract_predefined_default_object_acl(request, context)
            )
            if (
                predefined_default_object_acl
                == CommonEnums.PredefinedObjectAcl.PREDEFINED_OBJECT_ACL_UNSPECIFIED
            ):
                predefined_default_object_acl = (
                    CommonEnums.PredefinedObjectAcl.OBJECT_ACL_PROJECT_PRIVATE
                )
            elif predefined_default_object_acl == "":
                predefined_default_object_acl = "projectPrivate"
            elif is_uniform:
                testbench.error.invalid(
                    "Predefined Default Object ACL with uniform bucket level access enabled",
                    context,
                )
            cls.__insert_predefined_default_object_acl(
                metadata, predefined_default_object_acl, context
            )
        cls.__enrich_acl(metadata)
        metadata.iam_configuration.uniform_bucket_level_access.enabled = is_uniform
        metadata.id = metadata.name
        metadata.project_number = int(testbench.acl.PROJECT_NUMBER)
        metadata.metageneration = 0
        metadata.etag = hashlib.md5(metadata.name.encode("utf-8")).hexdigest()
        metadata.time_created.FromDatetime(time_created)
        metadata.updated.FromDatetime(time_created)
        metadata.owner.entity = testbench.acl.get_project_entity("owners", context)
        metadata.owner.entity_id = hashlib.md5(
            metadata.owner.entity.encode("utf-8")
        ).hexdigest()
        if rest_only is None:
            rest_only = {}
        return (
            cls(metadata, {}, cls.__init_iam_policy(metadata, context), rest_only),
            testbench.common.extract_projection(request, default_projection, context),
        )

    # === IAM === #

    @classmethod
    def __init_iam_policy(cls, metadata, context):
        role_mapping = {
            "READER": "roles/storage.legacyBucketReader",
            "WRITER": "roles/storage.legacyBucketWriter",
            "OWNER": "roles/storage.legacyBucketOwner",
        }
        bindings = []
        for entry in metadata.acl:
            legacy_role = entry.role
            if legacy_role is None or entry.entity is None:
                testbench.error.invalid("ACL entry", context)
            role = role_mapping.get(legacy_role)
            if role is None:
                testbench.error.invalid("Legacy role %s" % legacy_role, context)
            bindings.append(policy_pb2.Binding(role=role, members=[entry.entity]))
        return policy_pb2.Policy(
            version=1,
            bindings=bindings,
            etag=datetime.datetime.now().isoformat().encode("utf-8"),
        )
