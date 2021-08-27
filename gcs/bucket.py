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
import random
import re
import scalpl

from google.storage.v2 import storage_pb2
from google.iam.v1 import policy_pb2
from google.protobuf import field_mask_pb2, json_format

import testbench


class Bucket:
    modifiable_fields = {
        "acl",
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
        "location_type",
        "iam_config",
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
    def __preprocess_rest_ubla(cls, ubla):
        return testbench.common.rest_adjust(
            ubla, {"lockedTime": lambda x: ("lockTime", x)}
        )

    @classmethod
    def __preprocess_rest_pap(cls, pap):
        pap = pap.upper()
        if pap == "UNSPECIFIED":
            return "PUBLIC_ACCESS_PREVENTION_UNSPECIFIED"
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
    def __preprocess_rest(cls, rest):
        rest = testbench.common.rest_adjust(
            rest,
            {
                "name": lambda x: ("name", x),
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
    def __postprocess_rest_ubla(cls, ubla):
        return testbench.common.rest_adjust(
            ubla, {"lockTime": lambda x: ("lockedTime", x)}
        )

    @classmethod
    def __postprocess_rest_pap(cls, pap):
        pap = pap.lower()
        if pap == "public_access_prevention_unspecified":
            return "unspecified"
        return pap

    @classmethod
    def __postprocess_rest_iam_configuration(cls, config):
        return testbench.common.rest_adjust(
            config,
            {
                "publicAccessPrevention": lambda x: (
                    "publicAccessPrevention",
                    Bucket.__postprocess_rest_pap(x),
                ),
                "uniformBucketLevelAccess": lambda x: (
                    "uniformBucketLevelAccess",
                    Bucket.__postprocess_rest_ubla(x),
                ),
            },
        )

    @classmethod
    def __postprocess_rest_encryption(cls, enc):
        return testbench.common.rest_adjust(
            enc, {"defaultKmsKey": lambda x: ("defaultKmsKeyName", x)}
        )

    @classmethod
    def __postprocess_rest_date(cls, date):
        return "%04d-%02d-%02d" % (
            date.get("year", ""),
            date.get("month", ""),
            date.get("day", ""),
        )

    @classmethod
    def __postprocess_rest_condition(cls, condition):
        return testbench.common.rest_adjust(
            condition,
            {
                "ageDays": lambda x: ("age", x),
                "createdBefore": lambda x: (
                    "createdBefore",
                    cls.__postprocess_rest_date(x),
                ),
                "customTimeBefore": lambda x: (
                    "customTimeBefore",
                    cls.__postprocess_rest_date(x),
                ),
                "noncurrentTimeBefore": lambda x: (
                    "noncurrentTimeBefore",
                    cls.__postprocess_rest_date(x),
                ),
            },
        )

    @classmethod
    def __postprocess_rest_rule(cls, rule):
        return testbench.common.rest_adjust(
            rule,
            {
                "condition": lambda x: (
                    "condition",
                    Bucket.__postprocess_rest_condition(x),
                )
            },
        )

    @classmethod
    def __postprocess_rest_lifecycle(cls, lc):
        rules = lc.pop("rule", None)
        if rules is not None:
            lc["rule"] = [Bucket.__postprocess_rest_rule(r) for r in rules]
        return lc

    @classmethod
    def __postprocess_rest_bucket_acl(cls, bucket_name, acl):
        copy = acl.copy()
        copy["kind"] = "storage#bucketAccessControl"
        copy["bucket"] = bucket_name
        copy["etag"] = hashlib.md5(
            "#".join([copy["bucket"], copy["entity"], copy["role"]]).encode("utf-8")
        ).hexdigest()
        return copy

    @classmethod
    def __postprocess_rest_default_object_acl(cls, bucket_name, acl):
        copy = acl.copy()
        copy["kind"] = "storage#objectAccessControl"
        copy["bucket"] = bucket_name
        copy["etag"] = hashlib.md5(
            "#".join([copy["bucket"], copy["entity"], copy["role"]]).encode("utf-8")
        ).hexdigest()
        return copy

    @classmethod
    def __postprocess_rest(cls, data):
        bucket_name = data["name"]
        data = testbench.common.rest_adjust(
            data,
            {
                "bucketId": lambda x: ("id", x),
                "project": lambda x: ("projectNumber", x.replace("project/", "")),
                "createTime": lambda x: ("timeCreated", x),
                "updateTime": lambda x: ("updated", x),
                "iamConfig": lambda x: (
                    "iamConfiguration",
                    Bucket.__postprocess_rest_iam_configuration(x),
                ),
                "encryption": lambda x: (
                    "encryption",
                    Bucket.__postprocess_rest_encryption(x),
                ),
                "lifecycle": lambda x: (
                    "lifecycle",
                    Bucket.__postprocess_rest_lifecycle(x),
                ),
                "acl": lambda x: (
                    "acl",
                    [Bucket.__postprocess_rest_bucket_acl(bucket_name, a) for a in x],
                ),
                "defaultObjectAcl": lambda x: (
                    "defaultObjectAcl",
                    [
                        Bucket.__postprocess_rest_default_object_acl(bucket_name, a)
                        for a in x
                    ],
                ),
            },
        )
        data["kind"] = "storage#bucket"
        data["etag"] = base64.b64encode(data["updated"].encode("utf-8")).decode("utf-8")
        # 0 is the default in the proto, and hidden json_format.*
        if "metageneration" not in data:
            data["metageneration"] = 0
        return data

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
        if (
            predefined_default_object_acl == ""
            or predefined_default_object_acl
            == storage_pb2.PREDEFINED_OBJECT_ACL_UNSPECIFIED
        ):
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
    def init(cls, request, context):
        time_created = datetime.datetime.now()
        metadata = cls.__preprocess_rest(json.loads(request.data))
        metadata = json_format.ParseDict(metadata, storage_pb2.Bucket())
        cls.__validate_json_bucket_name(metadata.name, context)
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
                predefined_default_object_acl
                == storage_pb2.PREDEFINED_OBJECT_ACL_UNSPECIFIED
            ):
                predefined_default_object_acl = storage_pb2.OBJECT_ACL_PROJECT_PRIVATE
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
        metadata.iam_config.uniform_bucket_level_access.enabled = is_uniform
        metadata.bucket_id = metadata.name
        metadata.project = "project/" + testbench.acl.PROJECT_NUMBER
        metadata.metageneration = 1
        metadata.create_time.FromDatetime(time_created)
        metadata.update_time.FromDatetime(time_created)
        metadata.owner.entity = testbench.acl.get_project_entity("owners", context)
        metadata.owner.entity_id = hashlib.md5(
            metadata.owner.entity.encode("utf-8")
        ).hexdigest()
        return (
            cls(metadata, {}, cls.__init_iam_policy(metadata, context)),
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

    def get_iam_policy(self, request, context):
        return self.iam_policy

    def set_iam_policy(self, request, context):
        data = json.loads(request.data)
        if "iam_request" in data:
            data = data["iam_request"]["policy"]
        data.pop("kind", None)
        data.pop("etag", None)
        data.pop("resourceId", None)
        policy = json_format.ParseDict(data, policy_pb2.Policy())
        self.iam_policy = policy
        self.iam_policy.etag = datetime.datetime.now().isoformat().encode("utf-8")
        return self.iam_policy

    # === METADATA === #

    def __update_metadata(self, source, update_mask):
        if update_mask is None:
            update_mask = field_mask_pb2.FieldMask(paths=Bucket.modifiable_fields)
        update_mask.MergeMessage(source, self.metadata, True, True)
        self.metadata.metageneration += 1
        self.metadata.update_time.FromDatetime(datetime.datetime.now())

    def update(self, request, context):
        # Support for `Bucket: update` over gRPC is not needed (and not implemented).
        assert context is None
        data = self.__preprocess_rest(json.loads(request.data))
        metadata = json_format.ParseDict(data, storage_pb2.Bucket())
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
        else:
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

    def insert_notification(self, request, context):
        notification = {
            "kind": "storage#notification",
            "id": "notification-%d" % random.getrandbits(16),
        }
        data = json.loads(request.data)
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
        response = json_format.MessageToDict(self.metadata)
        return Bucket.__postprocess_rest(response)
