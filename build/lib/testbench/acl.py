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

"""Utils related to access control"""

import hashlib
import os

import testbench
from google.storage.v2 import storage_pb2

PROJECT_NUMBER = os.getenv(
    "GOOGLE_CLOUD_CPP_STORAGE_EMULATOR_PROJECT_NUMBER", "123456789"
)
OBJECT_OWNER_ENTITY = os.getenv(
    "GOOGLE_CLOUD_CPP_STORAGE_EMULATOR_OBJECT_OWNER_ENTITY",
    "user-object.owners@example.com",
)
OBJECT_READER_ENTITY = os.getenv(
    "GOOGLE_CLOUD_CPP_STORAGE_EMULATOR_OBJECT_READER_ENTITY",
    "user-object.viewers@example.com",
)


# === EXTRACT INFORMATION FROM ENTITY === #


def __extract_email(entity):
    if entity.startswith("user-"):
        return entity[len("user-") :]
    elif entity.startswith("group-") and "@" in entity:
        return entity[len("group-") :]
    return ""


def __extract_domain(entity):
    if entity.startswith("domain-"):
        return entity[len("domain-") :]
    return ""


def __extract_team(entity):
    if entity.startswith("project-"):
        return entity.split("-")[1]
    return ""


# === ENTITY UTILS === #


def get_canonical_entity(entity):
    if entity == "allUsers" or entity == "allAuthenticatedUsers":
        return entity
    if entity.startswith("project-owners-"):
        entity = "project-owners-" + PROJECT_NUMBER
    if entity.startswith("project-editors-"):
        entity = "project-editors-" + PROJECT_NUMBER
    if entity.startswith("project-viewers-"):
        entity = "project-viewers-" + PROJECT_NUMBER
    return entity.lower()


def get_project_entity(team, context):
    if team not in ["editors", "owners", "viewers"]:
        testbench.error.invalid("Team %s for project" % team, context)
    return "project-%s-%s" % (team, PROJECT_NUMBER)


def get_object_entity(role, context):
    if role == "OWNER":
        return OBJECT_OWNER_ENTITY
    elif role == "READER":
        return OBJECT_READER_ENTITY
    else:
        testbench.error.invalid("Role %s for object acl" % role, context)


# === CREATE ACL === #


def create_bucket_acl(
    bucket_name: str, entity: str, role: str, context
) -> storage_pb2.BucketAccessControl:
    canonical = get_canonical_entity(entity)
    if role not in ["OWNER", "WRITER", "READER"]:
        testbench.error.invalid("Role %s for bucket acl" % role, context)
    id = hashlib.md5(
        "#".join([bucket_name, canonical, role]).encode("utf-8")
    ).hexdigest()
    etag = hashlib.md5("#".join([canonical, role]).encode("utf-8")).hexdigest()
    acl = storage_pb2.BucketAccessControl(
        role=role,
        id=id,
        etag=etag,
        entity=canonical,
        entity_id=hashlib.md5(canonical.encode("utf-8")).hexdigest(),
        email=__extract_email(canonical),
        domain=__extract_domain(canonical),
        project_team={
            "project_number": PROJECT_NUMBER,
            "team": __extract_team(canonical),
        },
    )
    if canonical != entity:
        acl.entity_alt = entity
    return acl


def create_default_object_acl(
    bucket_name: str, entity: str, role: str, context
) -> storage_pb2.ObjectAccessControl:
    canonical = get_canonical_entity(entity)
    if role not in ["OWNER", "READER"]:
        testbench.error.invalid("Role %s for object acl" % role, context)
    id = hashlib.md5(
        "#".join([bucket_name, canonical, role]).encode("utf-8")
    ).hexdigest()
    etag = hashlib.md5("#".join([canonical, role]).encode("utf-8")).hexdigest()
    acl = storage_pb2.ObjectAccessControl(
        role=role,
        entity=canonical,
        id=id,
        etag=etag,
        entity_id=hashlib.md5(canonical.encode("utf-8")).hexdigest(),
        email=__extract_email(canonical),
        domain=__extract_domain(canonical),
        project_team={
            "project_number": PROJECT_NUMBER,
            "team": __extract_team(canonical),
        },
    )
    if canonical != entity:
        acl.entity_alt = entity
    return acl


def create_object_acl_from_default_object_acl(
    object_name: str,
    generation,
    default_object_acl: storage_pb2.ObjectAccessControl,
    context,
) -> storage_pb2.ObjectAccessControl:
    acl = storage_pb2.ObjectAccessControl()
    acl.CopyFrom(default_object_acl)
    acl.id = hashlib.md5(
        (object_name + str(generation) + acl.entity + acl.role).encode("utf-8")
    ).hexdigest()
    return acl


def create_object_acl(
    bucket_name: str, object_name: str, generation: int, entity: str, role: str, context
) -> storage_pb2.ObjectAccessControl:
    default_object_acl = create_default_object_acl(bucket_name, entity, role, context)
    acl = create_object_acl_from_default_object_acl(
        object_name, generation, default_object_acl, context
    )
    return acl


# === EXTRACT INFORMATION FROM REQUEST === #


def extract_predefined_acl(request, is_destination, context):
    if context is not None:
        extract_field = (
            "predefined_acl" if not is_destination else "destination_predefined_acl"
        )
        return getattr(request, extract_field, None)
    else:
        extract_field = (
            "predefinedAcl" if not is_destination else "destinationPredefinedAcl"
        )
        return request.args.get(extract_field, "")


def extract_predefined_default_object_acl(request, context):
    return request.args.get("predefinedDefaultObjectAcl", "")


# === COMPUTE PREDEFINED ACL === #


def compute_predefined_bucket_acl(bucket_name, predefined_acl, context):
    if predefined_acl is None:
        return []
    predefined_acl = testbench.common.to_snake_case(predefined_acl)
    predefined_acl = predefined_acl.replace("-", "_")
    acls = []
    if predefined_acl == "authenticated_read":
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
        acls.append(
            create_bucket_acl(bucket_name, "allAuthenticatedUsers", "READER", context)
        )
    elif predefined_acl == "private":
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
    elif predefined_acl == "project_private":
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("editors", context), "WRITER", context
            )
        )
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("viewers", context), "READER", context
            )
        )
    elif predefined_acl == "public_read":
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
        acls.append(create_bucket_acl(bucket_name, "allUsers", "READER", context))
    elif predefined_acl == "public_read_write":
        acls.append(
            create_bucket_acl(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
        acls.append(create_bucket_acl(bucket_name, "allUsers", "WRITER", context))
    return acls


def __compute_predefined_object_acl(bucket_name, predefined_acl, acl_factory, context):
    if predefined_acl is None:
        return []
    predefined_acl = testbench.common.to_snake_case(predefined_acl)
    predefined_acl = predefined_acl.replace("-", "_")
    acls = []
    if predefined_acl == "authenticated_read":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(bucket_name, "allAuthenticatedUsers", "READER", context)
        )
    elif predefined_acl == "bucket_owner_full_control":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
    elif predefined_acl == "bucket_owner_read":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(
                bucket_name, get_project_entity("owners", context), "READER", context
            )
        )
    elif predefined_acl == "private":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
    elif predefined_acl == "project_private":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(
                bucket_name, get_project_entity("owners", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(
                bucket_name, get_project_entity("editors", context), "OWNER", context
            )
        )
        acls.append(
            acl_factory(
                bucket_name, get_project_entity("viewers", context), "READER", context
            )
        )
    elif predefined_acl == "public_read":
        acls.append(
            acl_factory(
                bucket_name, get_object_entity("OWNER", context), "OWNER", context
            )
        )
        acls.append(acl_factory(bucket_name, "allUsers", "READER", context))
    return acls


def compute_predefined_default_object_acl(
    bucket_name, predefined_default_object_acl, context
):
    return __compute_predefined_object_acl(
        bucket_name, predefined_default_object_acl, create_default_object_acl, context
    )


def compute_predefined_object_acl(
    bucket_name, object_name, generation, predefined_acl, context
):
    def object_acl_factory(bucket_name, entity, role, context):
        return create_object_acl(
            bucket_name, object_name, generation, entity, role, context
        )

    return __compute_predefined_object_acl(
        bucket_name, predefined_acl, object_acl_factory, context
    )
