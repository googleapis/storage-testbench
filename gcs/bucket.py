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

import base64
import datetime
import hashlib
import json
import re
import uuid

from google.protobuf import field_mask_pb2, json_format

import testbench
from google.iam.v1 import policy_pb2
from google.storage.v2 import storage_pb2


class Bucket:
    modifiable_fields = {
        "acl",
        "autoclass",
        "default_object_acl",
        "lifecycle",
        "cors",
        "storage_class",
        "default_event_based_hold",
        "labels",
        "website",
        "versioning",
        "logging",
        "encryption",
        "billing",
        "retention_policy",
        "soft_delete_policy",
        "location_type",
        "iam_config",
        "rpo",
    }

    def __init__(self, metadata, notifications, iam_policy):
        self.metadata = metadata
        self.notifications = notifications
        self.iam_policy = iam_policy

    @classmethod
    def __validate_json_bucket_name(cls, bucket_name, context):
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
    def __validate_grpc_project_name(cls, project_name, context):
        valid = re.match("^projects/[^/]+$", project_name) is not None
        if not valid:
            testbench.error.invalid("Project name %s" % project_name, context)

    @classmethod
    def __preprocess_rest_ubla(cls, ubla):
        return testbench.common.rest_adjust(
            ubla, {"lockedTime": lambda x: ("lockTime", x)}
        )

    @classmethod
    def __preprocess_rest_pap(cls, pap):
        pap = pap.upper()
        if pap == "UNSPECIFIED" or pap == "INHERITED":
            return "INHERITED"
        return pap

    @classmethod
    def __preprocess_rest_iam_configuration(cls, config):
        config = testbench.common.rest_adjust(
            config,
            {
                "uniformBucketLevelAccess": lambda x: (
                    "uniformBucketLevelAccess",
                    Bucket.__preprocess_rest_ubla(x),
                ),
                "publicAccessPrevention": lambda x: (
                    "publicAccessPrevention",
                    Bucket.__preprocess_rest_pap(x),
                ),
            },
        )
        return config

    @classmethod
    def __preprocess_rest_encryption(cls, enc):
        return testbench.common.rest_adjust(
            enc, {"defaultKmsKeyName": lambda x: ("defaultKmsKey", x)}
        )

    @classmethod
    def __preprocess_rest_date(cls, date):
        year, month, day = date.split("-", 3)
        return {"year": year, "month": month, "day": day}

    @classmethod
    def __preprocess_rest_condition(cls, condition):
        return testbench.common.rest_adjust(
            condition,
            {
                "age": lambda x: ("ageDays", x),
                "createdBefore": lambda x: (
                    "createdBefore",
                    cls.__preprocess_rest_date(x),
                ),
                "customTimeBefore": lambda x: (
                    "customTimeBefore",
                    cls.__preprocess_rest_date(x),
                ),
                "noncurrentTimeBefore": lambda x: (
                    "noncurrentTimeBefore",
                    cls.__preprocess_rest_date(x),
                ),
            },
        )

    @classmethod
    def __preprocess_rest_rule(cls, rule):
        return testbench.common.rest_adjust(
            rule,
            {
                "condition": lambda x: (
                    "condition",
                    Bucket.__preprocess_rest_condition(x),
                )
            },
        )

    @classmethod
    def __preprocess_rest_lifecyle(cls, lc):
        rules = lc.pop("rule", None)
        if rules is not None:
            lc["rule"] = [Bucket.__preprocess_rest_rule(r) for r in rules]
        return lc

    @classmethod
    def __preprocess_rest_acl(cls, acl):
        copy = acl.copy()
        for k in ["kind", "bucket", "etag"]:
            copy.pop(k, None)
        return copy

    @classmethod
    def __preprocess_rest_default_object_acl(cls, acl):
        copy = acl.copy()
        for k in ["kind", "bucket", "object", "etag"]:
            copy.pop(k, None)
        return copy

    @classmethod
    def __preprocess_rest_retention_period(cls, rp):
        # The JSON representation for a proto duration is a string in basically
        # this format "%{seconds + nanos/1'000'000'000.0}s", the 'nanos' are
        # always zero.
        return f"{rp}s"

    @classmethod
    def __preprocess_rest_retention_policy(cls, rp):
        return testbench.common.rest_adjust(
            rp,
            {
                "retentionPeriod": lambda x: (
                    "retentionDuration",
                    Bucket.__preprocess_rest_retention_period(x),
                ),
            },
        )

    @classmethod
    def __preprocess_rest_soft_delete_retention_duration(cls, rp):
        # The JSON representation for a proto duration is a string in basically
        # this format "%{seconds + nanos/1'000'000'000.0}s". For this field
        # type the nanos should always be zero.
        return f"{rp}s"

    @classmethod
    def __preprocess_rest_soft_delete_policy(cls, rp):
        return testbench.common.rest_adjust(
            rp,
            {
                "retentionDurationSeconds": lambda x: (
                    "retentionDuration",
                    Bucket.__preprocess_rest_soft_delete_retention_duration(x),
                ),
            },
        )

    @classmethod
    def __preprocess_rest(cls, rest):
        rest = testbench.common.rest_adjust(
            rest,
            {
                "name": lambda x: ("name", testbench.common.bucket_name_to_proto(x)),
                "id": lambda x: ("bucketId", x),
                "kind": lambda x: (None, None),
                "etag": lambda x: (None, None),
                "projectNumber": lambda x: ("project", x),
                "timeCreated": lambda x: ("create_time", x),
                "updated": lambda x: ("update_time", x),
                "iamConfiguration": lambda x: (
                    "iamConfig",
                    Bucket.__preprocess_rest_iam_configuration(x),
                ),
                "encryption": lambda x: (
                    "encryption",
                    Bucket.__preprocess_rest_encryption(x),
                ),
                "lifecycle": lambda x: (
                    "lifecycle",
                    Bucket.__preprocess_rest_lifecyle(x),
                ),
                "retentionPolicy": lambda x: (
                    "retentionPolicy",
                    Bucket.__preprocess_rest_retention_policy(x),
                ),
                "softDeletePolicy": lambda x: (
                    "softDeletePolicy",
                    Bucket.__preprocess_rest_soft_delete_policy(x),
                ),
            },
        )
        if rest.get("acl", None) is not None:
            rest["acl"] = [Bucket.__preprocess_rest_acl(a) for a in rest.get("acl")]
        if rest.get("defaultObjectAcl", None) is not None:
            rest["defaultObjectAcl"] = [
                Bucket.__preprocess_rest_default_object_acl(a)
                for a in rest.get("defaultObjectAcl")
            ]
        return rest

    @classmethod
    def __insert_predefined_acl(cls, metadata, predefined_acl, context):
        if predefined_acl == "" or predefined_acl == "unspecified":
            return
        if metadata.iam_config.uniform_bucket_level_access.enabled:
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
        if predefined_default_object_acl is None or predefined_default_object_acl == "":
            return
        if metadata.iam_config.uniform_bucket_level_access.enabled:
            testbench.error.invalid(
                "Predefined Default Object ACL with uniform bucket level access enabled",
                context,
            )
        acls = testbench.acl.compute_predefined_default_object_acl(
            metadata.name, predefined_default_object_acl, context
        )
        del metadata.default_object_acl[:]
        metadata.default_object_acl.extend(acls)

    # === INITIALIZATION === #

    @classmethod
    def _metadata_etag(cls, metadata):
        return hashlib.md5(("%d" % metadata.metageneration).encode("utf-8")).hexdigest()

    @classmethod
    def _init_defaults(cls, metadata: storage_pb2.Bucket, context):
        time_created = datetime.datetime.now()
        if metadata.rpo is None or metadata.rpo == "":
            metadata.rpo = "DEFAULT"
        if metadata.storage_class is None or metadata.storage_class == "":
            metadata.storage_class = "STANDARD"
        metadata.project = "projects/" + testbench.acl.PROJECT_NUMBER
        metadata.create_time.FromDatetime(time_created)
        metadata.update_time.FromDatetime(time_created)
        if metadata.autoclass.enabled:
            metadata.autoclass.toggle_time.FromDatetime(time_created)
        metadata.metageneration = 1
        metadata.owner.entity = testbench.acl.get_project_entity("owners", context)
        metadata.owner.entity_id = hashlib.md5(
            metadata.owner.entity.encode("utf-8")
        ).hexdigest()
        metadata.etag = cls._metadata_etag(metadata)

    @classmethod
    def __validate_soft_delete_policy(cls, metadata, context):
        if not metadata.HasField("soft_delete_policy"):
            return
        policy = metadata.soft_delete_policy
        if policy.retention_duration.nanos != 0:
            testbench.error.invalid(
                "SoftDeletePolicy.retention_duration should not have nanoseconds",
                context,
            )
        if policy.retention_duration.ToSeconds() < 7 * 86400:
            testbench.error.invalid(
                "SoftDeletePolicy.retention_duration should be at least 7 days", context
            )
        if policy.retention_duration.ToSeconds() >= 90 * 86400:
            testbench.error.invalid(
                "SoftDeletePolicy.retention_duration should be less than 90 days",
                context,
            )

    @classmethod
    def init(cls, request, context):
        metadata = cls.__preprocess_rest(json.loads(request.data))
        metadata = json_format.ParseDict(metadata, storage_pb2.Bucket())
        cls._init_defaults(metadata, context)
        cls.__validate_json_bucket_name(
            testbench.common.bucket_name_from_proto(metadata.name), context
        )
        default_projection = "noAcl"
        if len(metadata.acl) != 0 or len(metadata.default_object_acl) != 0:
            default_projection = "full"
        is_uniform = metadata.iam_config.uniform_bucket_level_access.enabled
        metadata.iam_config.uniform_bucket_level_access.enabled = False
        if len(metadata.acl) == 0:
            predefined_acl = testbench.acl.extract_predefined_acl(
                request, False, context
            )
            if predefined_acl == "unspecified" or predefined_acl == "":
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
                predefined_default_object_acl is None
                or predefined_default_object_acl == ""
            ):
                predefined_default_object_acl = "projectPrivate"
            elif is_uniform:
                testbench.error.invalid(
                    "Predefined Default Object ACL with uniform bucket level access enabled",
                    context,
                )
            cls.__insert_predefined_default_object_acl(
                metadata, predefined_default_object_acl, context
            )
        metadata.iam_config.uniform_bucket_level_access.enabled = is_uniform
        metadata.bucket_id = testbench.common.bucket_name_from_proto(metadata.name)
        metadata.project = "projects/" + testbench.acl.PROJECT_NUMBER
        if metadata.HasField("soft_delete_policy"):
            metadata.soft_delete_policy.effective_time.FromDatetime(
                datetime.datetime.now()
            )
        cls.__validate_soft_delete_policy(metadata, context)
        return (
            cls(metadata, {}, cls.__init_iam_policy(metadata, context)),
            testbench.common.extract_projection(request, default_projection, context),
        )

    @classmethod
    def init_grpc(cls, request, context):
        cls.__validate_json_bucket_name(
            testbench.common.bucket_name_from_proto(request.bucket_id), context
        )
        if request.parent == "projects/_":
            cls.__validate_grpc_project_name(request.bucket.project, context)
        else:
            cls.__validate_grpc_project_name(request.parent, context)
            if request.bucket.project != "":
                testbench.error.invalid(
                    "CreateBucketRequest with invalid combination of `parent` and `bucket.project` fields",
                    context,
                )
        metadata = request.bucket
        cls._init_defaults(metadata, context)
        metadata.bucket_id = request.bucket_id
        metadata.name = "projects/_/buckets/" + request.bucket_id
        predefined_acl = "projectPrivate"
        if request.predefined_acl is not None and request.predefined_acl != "":
            predefined_acl = request.predefined_acl
        predefined_default_object_acl = (
            request.predefined_default_object_acl
            if request.predefined_default_object_acl != ""
            else "projectPrivate"
        )
        cls.__insert_predefined_acl(metadata, predefined_acl, context)
        cls.__insert_predefined_default_object_acl(
            metadata, predefined_default_object_acl, context
        )
        if metadata.HasField("soft_delete_policy"):
            metadata.soft_delete_policy.effective_time.FromDatetime(
                datetime.datetime.now()
            )
        cls.__validate_soft_delete_policy(metadata, context)
        return (cls(metadata, {}, cls.__init_iam_policy(metadata, context)), "noAcl")

    # === IAM === #

    @classmethod
    def __iam_etag(cls):
        return uuid.uuid4().hex.encode("utf-8")

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
            etag=cls.__iam_etag(),
        )

    def get_iam_policy(self, request, context):
        return self.iam_policy

    def set_iam_policy(self, request, context):
        if context is not None:
            if (
                request.policy.etag != ""
                and request.policy.etag != self.iam_policy.etag
            ):
                return testbench.error.mismatch(
                    "etag",
                    expect=self.iam_policy.etag,
                    actual=request.policy.etag,
                    context=context,
                )
            self.iam_policy.CopyFrom(request.policy)
            self.iam_policy.etag = Bucket.__iam_etag()
            return self.iam_policy
        data = json.loads(request.data)
        if "iam_request" in data:
            data = data["iam_request"]["policy"]
        data.pop("kind", None)
        data.pop("etag", None)
        data.pop("resourceId", None)
        policy = json_format.ParseDict(data, policy_pb2.Policy())
        self.iam_policy = policy
        self.iam_policy.etag = Bucket.__iam_etag()
        return self.iam_policy

    # === METADATA === #

    def __update_metadata(self, source, update_mask):
        if update_mask is None:
            update_mask = field_mask_pb2.FieldMask(paths=Bucket.modifiable_fields)
        update_mask.MergeMessage(source, self.metadata, True, True)
        now = datetime.datetime.now()
        if "autoclass" in update_mask.paths and source.HasField("autoclass"):
            self.metadata.autoclass.toggle_time.FromDatetime(now)
        if "soft_delete_policy" in update_mask.paths and source.HasField(
            "soft_delete_policy"
        ):
            self.metadata.soft_delete_policy.effective_time.FromDatetime(now)
        self.metadata.metageneration += 1
        self.metadata.update_time.FromDatetime(now)
        self.metadata.etag = Bucket._metadata_etag(self.metadata)

    def update(self, request, context):
        # Support for `Bucket: update` over gRPC is not needed (and not implemented).
        assert context is None
        data = self.__preprocess_rest(json.loads(request.data))
        metadata = json_format.ParseDict(data, storage_pb2.Bucket())
        Bucket.__validate_soft_delete_policy(metadata, context)
        self.__update_metadata(metadata, None)
        self.__insert_predefined_acl(
            metadata,
            testbench.acl.extract_predefined_acl(request, False, context),
            context,
        )
        self.__insert_predefined_default_object_acl(
            metadata,
            testbench.acl.extract_predefined_default_object_acl(request, context),
            context,
        )

    def patch(self, request, context):
        # Support for `Bucket: patch` over gRPC is not needed (and not implemented).
        assert context is None
        rest = self.__preprocess_rest(
            testbench.common.rest_patch(self.rest(), json.loads(request.data))
        )
        metadata = json_format.ParseDict(rest, storage_pb2.Bucket())
        Bucket.__validate_soft_delete_policy(metadata, context)
        self.__update_metadata(metadata, None)
        self.__insert_predefined_acl(
            metadata,
            testbench.acl.extract_predefined_acl(request, False, context),
            context,
        )
        self.__insert_predefined_default_object_acl(
            metadata,
            testbench.acl.extract_predefined_default_object_acl(request, context),
            context,
        )

    # === ACL === #

    def __search_acl(self, entity, must_exist, context):
        entity = testbench.acl.get_canonical_entity(entity)
        for i in range(len(self.metadata.acl)):
            if self.metadata.acl[i].entity == entity:
                return i
        if must_exist:
            testbench.error.notfound("ACL %s" % entity, context)

    def __upsert_acl(self, entity, role, context):
        # For simplicity, we treat `insert`, `update` and `patch` ACL the same way.
        index = self.__search_acl(entity, False, context)
        acl = testbench.acl.create_bucket_acl(self.metadata.name, entity, role, context)
        if index is not None:
            self.metadata.acl[index].CopyFrom(acl)
            return self.metadata.acl[index]
        self.metadata.acl.append(acl)
        return acl

    def get_acl(self, entity, context):
        index = self.__search_acl(entity, True, context)
        return self.metadata.acl[index]

    def insert_acl(self, request, context):
        payload = json.loads(request.data)
        entity, role = payload["entity"], payload["role"]
        return self.__upsert_acl(entity, role, context)

    def update_acl(self, request, entity, context):
        payload = json.loads(request.data)
        role = payload["role"]
        return self.__upsert_acl(entity, role, context)

    def patch_acl(self, request, entity, context):
        payload = json.loads(request.data)
        role = payload["role"]
        return self.__upsert_acl(entity, role, context)

    def delete_acl(self, entity, context):
        del self.metadata.acl[self.__search_acl(entity, True, context)]

    # === DEFAULT OBJECT ACL === #

    def __search_default_object_acl(self, entity, must_exist, context):
        entity = testbench.acl.get_canonical_entity(entity)
        for i in range(len(self.metadata.default_object_acl)):
            if self.metadata.default_object_acl[i].entity == entity:
                return i
        if must_exist:
            testbench.error.notfound("Default Object ACL %s" % entity, context)

    def __upsert_default_object_acl(self, entity, role, context):
        # For simplicity, we treat `insert`, `update` and `patch` Default Object ACL the same way.
        index = self.__search_default_object_acl(entity, False, context)
        acl = testbench.acl.create_default_object_acl(
            self.metadata.name, entity, role, context
        )
        if index is not None:
            self.metadata.default_object_acl[index].CopyFrom(acl)
            return self.metadata.default_object_acl[index]
        else:
            self.metadata.default_object_acl.append(acl)
            return acl

    def get_default_object_acl(self, entity, context):
        index = self.__search_default_object_acl(entity, True, context)
        return self.metadata.default_object_acl[index]

    def insert_default_object_acl(self, request, context):
        payload = json.loads(request.data)
        entity, role = payload["entity"], payload["role"]
        return self.__upsert_default_object_acl(entity, role, context)

    def update_default_object_acl(self, request, entity, context):
        payload = json.loads(request.data)
        role = payload["role"]
        return self.__upsert_default_object_acl(entity, role, context)

    def patch_default_object_acl(self, request, entity, context):
        payload = json.loads(request.data)
        role = payload["role"]
        return self.__upsert_default_object_acl(entity, role, context)

    def delete_default_object_acl(self, entity, context):
        del self.metadata.default_object_acl[
            self.__search_default_object_acl(entity, True, context)
        ]

    # === NOTIFICATIONS === #

    def insert_notification(self, notification_rest: str, context):
        notification = {
            "kind": "storage#notification",
            "id": "notification-%s" % uuid.uuid4().hex,
        }
        data = json.loads(notification_rest)
        data = {testbench.common.to_snake_case(k): v for k, v in data.items()}
        for required_key in {"topic", "payload_format"}:
            value = data.pop(required_key, None)
            if value is not None:
                notification[required_key] = value
            else:
                testbench.error.invalid(
                    "Missing field in notification %s" % required_key, context
                )
        for key in {"event_types", "custom_attributes", "object_name_prefix"}:
            value = data.pop(key, None)
            if value is not None:
                notification[key] = value
        self.notifications[notification["id"]] = notification
        return notification

    def get_notification(self, notification_id, context):
        if notification_id not in self.notifications:
            testbench.error.notfound("Notification %s" % notification_id, context)
        return self.notifications[notification_id]

    def delete_notification(self, notification_id, context):
        if notification_id not in self.notifications:
            testbench.error.notfound("Notification %s" % notification_id, context)
        del self.notifications[notification_id]

    def list_notifications(self, context):
        response = {"kind": "storage#notifications", "items": []}
        for notification in self.notifications.values():
            response["items"].append(notification)
        return response

    # === RESPONSE === #

    def rest(self):
        return testbench.proto2rest.bucket_as_rest(self.metadata)
