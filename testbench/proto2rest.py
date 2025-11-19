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

import base64
import datetime
import struct

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
    copy.pop("entityAlt", None)
    return copy


def __postprocess_rest_default_object_acl(bucket_id, acl):
    copy = acl.copy()
    copy["kind"] = "storage#objectAccessControl"
    copy["bucket"] = bucket_id
    copy.pop("entityAlt", None)
    return copy


def __postprocess_rest_retention_policy_duration(data: str):
    # The string is in the canonical JSON representation for proto durations,
    # that is: "%{seconds + nanos/1'000'000'000}s", we are just going to
    # ignore the nanos and return this as a string.
    return str(int(data[:-1]))


def __postprocess_rest_retention_policy(data):
    return testbench.common.rest_adjust(
        data,
        {
            "retentionDuration": lambda x: (
                "retentionPeriod",
                __postprocess_rest_retention_policy_duration(x),
            )
        },
    )


def __postprocess_rest_soft_delete_policy_duration(data: str):
    # The string is in the canonical JSON representation for proto durations,
    # that is: "%{seconds + nanos/1'000'000'000}s", we are just going to
    # ignore the nanos and return this as a string.
    return str(int(data[:-1]))


def __postprocess_rest_soft_delete_policy(data):
    return testbench.common.rest_adjust(
        data,
        {
            "retentionDuration": lambda x: (
                "retentionDurationSeconds",
                __postprocess_rest_soft_delete_policy_duration(x),
            )
        },
    )


def __postprocess_rest_ip_filter(data):
    if data.get("vpcNetworkSources") is not None:
        sources = []
        for source in data.get("vpcNetworkSources"):
            sources.append(
                testbench.common.rest_adjust(
                    source,
                    {
                        "allowed_ip_cidr_ranges": lambda x: (
                            "allowedIpCidrRanges",
                            x,
                        )
                    },
                )
            )
        data["vpcNetworkSources"] = sources
    return testbench.common.rest_adjust(
        data,
        {
            "public_network_source": lambda x: (
                "publicNetworkSource",
                testbench.common.rest_adjust(
                    x,
                    {
                        "allowed_ip_cidr_ranges": lambda x: (
                            "allowedIpCidrRanges",
                            x,
                        )
                    },
                ),
            ),
            "vpc_network_sources": lambda x: ("vpcNetworkSources", x),
            "allow_cross_org_vpcs": lambda x: ("allowCrossOrgVpcs", x),
            "allow_all_service_agent_access": lambda x: (
                "allowAllServiceAgentAccess",
                x,
            ),
        },
    )


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
            "retentionPolicy": lambda x: (
                "retentionPolicy",
                __postprocess_rest_retention_policy(x),
            ),
            "softDeletePolicy": lambda x: (
                "softDeletePolicy",
                __postprocess_rest_soft_delete_policy(x),
            ),
            "ipFilter": lambda x: ("ipFilter", __postprocess_rest_ip_filter(x)),
        },
    )
    data["kind"] = "storage#bucket"
    # 0 is the default in the proto, and hidden by json_format.*
    if "metageneration" not in data:
        data["metageneration"] = 0
    return data


def __postprocess_customer_encryption(metadata):
    # There is no need to base64 encode the data, because json_format.MessageToDict() already does.
    return testbench.common.rest_adjust(
        metadata,
        {"keySha256Bytes": lambda x: ("keySha256", x)},
    )


def __postprocess_object_access_control(
    bucket_id, object_id, generation, access_control
):
    copy = access_control.copy()
    copy["kind"] = "storage#objectAccessControl"
    copy["bucket"] = bucket_id
    copy["object"] = object_id
    copy["generation"] = generation
    copy.pop("entityAlt", None)
    return copy


def __postprocess_object_rest(metadata):
    """The protos for storage/v2 renamed some fields in ways that require some custom coding."""
    # For some fields the storage/v2 name just needs to change slightly.
    bucket_id = testbench.common.bucket_name_from_proto(metadata.get("bucket", None))
    metadata = testbench.common.rest_adjust(
        metadata,
        {
            "bucket": lambda x: ("bucket", bucket_id),
            "createTime": lambda x: ("timeCreated", x),
            "finalizeTime": lambda x: ("timeFinalized", x),
            "updateTime": lambda x: ("updated", x),
            "kmsKey": lambda x: ("kmsKeyName", x),
            "retentionExpireTime": lambda x: ("retentionExpirationTime", x),
            "deleteTime": lambda x: ("timeDeleted", x),
            "updateStorageClassTime": lambda x: ("timeStorageClassUpdated", x),
            "customerEncryption": lambda x: (
                "customerEncryption",
                __postprocess_customer_encryption(x),
            ),
        },
    )
    metadata["kind"] = "storage#object"
    metadata["id"] = "%s/o/%s/%s" % (
        metadata["bucket"],
        metadata["name"],
        metadata["generation"],
    )
    # Checksums need special treatment
    cs = metadata.pop("checksums", None)
    if cs is not None:
        if "crc32c" in cs:
            metadata["crc32c"] = base64.b64encode(
                struct.pack(">I", cs["crc32c"])
            ).decode("utf-8")
        if "md5Hash" in cs:
            metadata["md5Hash"] = cs["md5Hash"]
    # Finally the ACLs, if present, require additional fields
    if "acl" in metadata:
        metadata["acl"] = [
            __postprocess_object_access_control(
                bucket_id, metadata["name"], metadata["generation"], a
            )
            for a in metadata["acl"]
        ]
    return metadata


def bucket_as_rest(bucket: storage_pb2.Bucket):
    metadata = json_format.MessageToDict(bucket)
    return __postprocess_bucket_rest(metadata)


def bucket_access_control_as_rest(bucket_id: str, acl: storage_pb2.BucketAccessControl):
    rest = json_format.MessageToDict(acl)
    return __postprocess_rest_bucket_acl(bucket_id, rest)


def object_as_rest(object: storage_pb2.Object):
    metadata = json_format.MessageToDict(object)
    return __postprocess_object_rest(metadata)


def object_access_control_as_rest(
    bucket_id: str,
    object_id: str,
    generation: str,
    metadata: storage_pb2.ObjectAccessControl,
):
    rest = json_format.MessageToDict(metadata)
    return __postprocess_object_access_control(bucket_id, object_id, generation, rest)


def default_object_access_control_as_rest(
    bucket_id: str, acl: storage_pb2.ObjectAccessControl
):
    rest = json_format.MessageToDict(acl)
    return __postprocess_rest_default_object_acl(bucket_id, rest)
