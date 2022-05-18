# Copyright 2022 Google LLC
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

"""
Convert resources from their proto representation to their REST representation.

The testbench keeps resources (buckets, objects, etc.) as protos. In the REST
APIs, we need to convert these types to their REST representation. For the
most part, we rely on `google.protobuf.json_format.MessageToDict()` to do
the heavy lifting. But some fields have different names, other fields are
missing in the proto representation, and some fields use different
representationsin. For example, bucket names in protos are
`projects/_/buckets/${bucket_id}`.

This module contains a number of helper functions to perform these transformations.
"""

import hashlib

from google.protobuf import json_format

from google.storage.v2 import storage_pb2

import testbench


def __postprocess_rest_ubla(ubla):
    return testbench.common.rest_adjust(ubla, {"lockTime": lambda x: ("lockedTime", x)})


def __postprocess_rest_pap(pap):
    return pap.lower()


def __postprocess_rest_iam_configuration(config):
    adjusted = testbench.common.rest_adjust(
        config,
        {
            "publicAccessPrevention": lambda x: (
                "publicAccessPrevention",
                __postprocess_rest_pap(x),
            ),
            "uniformBucketLevelAccess": lambda x: (
                "uniformBucketLevelAccess",
                __postprocess_rest_ubla(x),
            ),
        },
    )
    adjusted.setdefault("publicAccessPrevention", "inherited")
    return adjusted


def __postprocess_rest_encryption(enc):
    return testbench.common.rest_adjust(
        enc, {"defaultKmsKey": lambda x: ("defaultKmsKeyName", x)}
    )


def __postprocess_rest_date(date):
    return "%04d-%02d-%02d" % (
        date.get("year", ""),
        date.get("month", ""),
        date.get("day", ""),
    )


def __postprocess_rest_condition(condition):
    return testbench.common.rest_adjust(
        condition,
        {
            "ageDays": lambda x: ("age", x),
            "createdBefore": lambda x: (
                "createdBefore",
                __postprocess_rest_date(x),
            ),
            "customTimeBefore": lambda x: (
                "customTimeBefore",
                __postprocess_rest_date(x),
            ),
            "noncurrentTimeBefore": lambda x: (
                "noncurrentTimeBefore",
                __postprocess_rest_date(x),
            ),
        },
    )


def __postprocess_rest_rule(rule):
    return testbench.common.rest_adjust(
        rule,
        {
            "condition": lambda x: (
                "condition",
                __postprocess_rest_condition(x),
            )
        },
    )


def __postprocess_rest_lifecycle(lc):
    rules = lc.pop("rule", None)
    if rules is not None:
        lc["rule"] = [__postprocess_rest_rule(r) for r in rules]
    return lc


def __postprocess_rest_bucket_acl(bucket_id, acl):
    copy = acl.copy()
    copy["kind"] = "storage#bucketAccessControl"
    copy["bucket"] = bucket_id
    copy["etag"] = hashlib.md5(
        "#".join([copy["bucket"], copy["entity"], copy["role"]]).encode("utf-8")
    ).hexdigest()
    return copy


def __postprocess_rest_default_object_acl(bucket_id, acl):
    copy = acl.copy()
    copy["kind"] = "storage#objectAccessControl"
    copy["bucket"] = bucket_id
    copy["etag"] = hashlib.md5(
        "#".join([copy["bucket"], copy["entity"], copy["role"]]).encode("utf-8")
    ).hexdigest()
    return copy


def __postprocess_bucket_rest(data):
    bucket_id = testbench.common.bucket_name_from_proto(data["name"])
    data = testbench.common.rest_adjust(
        data,
        {
            "name": lambda x: ("name", bucket_id),
            "bucketId": lambda x: ("id", bucket_id),
            "project": lambda x: ("projectNumber", x.replace("projects/", "")),
            "createTime": lambda x: ("timeCreated", x),
            "updateTime": lambda x: ("updated", x),
            "iamConfig": lambda x: (
                "iamConfiguration",
                __postprocess_rest_iam_configuration(x),
            ),
            "encryption": lambda x: (
                "encryption",
                __postprocess_rest_encryption(x),
            ),
            "lifecycle": lambda x: (
                "lifecycle",
                __postprocess_rest_lifecycle(x),
            ),
            "acl": lambda x: (
                "acl",
                [__postprocess_rest_bucket_acl(bucket_id, a) for a in x],
            ),
            "defaultObjectAcl": lambda x: (
                "defaultObjectAcl",
                [__postprocess_rest_default_object_acl(bucket_id, a) for a in x],
            ),
        },
    )
    data["kind"] = "storage#bucket"
    data["etag"] = hashlib.md5(data["updated"].encode("utf-8")).hexdigest()
    # 0 is the default in the proto, and hidden by json_format.*
    if "metageneration" not in data:
        data["metageneration"] = 0
    return data


def bucket_as_rest(bucket: storage_pb2.Bucket):
    metadata = json_format.MessageToDict(bucket)
    return __postprocess_bucket_rest(metadata)


def bucket_access_control_as_rest(bucket_id: str, acl: storage_pb2.BucketAccessControl):
    rest = json_format.MessageToDict(acl)
    return __postprocess_rest_bucket_acl(bucket_id, rest)
