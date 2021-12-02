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

"""Common utils"""

import base64
from functools import wraps
import json
import random
import re
import socket
import struct
import types

import flask
from google.protobuf import timestamp_pb2
from grpc import StatusCode
from requests_toolbelt import MultipartDecoder
from requests_toolbelt.multipart.decoder import ImproperBodyPartContentException
import scalpl

from google.storage.v2 import storage_pb2
import testbench

re_remove_index = re.compile(r"\[\d+\]+|^[0-9]+")
retry_return_error_code = re.compile(r"return-([0-9]+)$")
retry_return_error_connection = re.compile(r"return-([a-z\-]+)$")
retry_return_error_after_bytes = re.compile(r"return-([0-9]+)-after-([0-9]+)K$")
retry_return_short_response = re.compile(r"return-broken-stream-final-chunk-after-([0-9]+)B$")
content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+|[0-9]+-\*)\/(\*|[0-9]+)")

# === STR === #


re_snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def to_snake_case(string):
    return re_snake_case.sub("_", string).lower()


def remove_index(string):
    return re_remove_index.sub("", string)


# === FAKE REQUEST === #


class FakeRequest(types.SimpleNamespace):
    """
    Adapt requests to JSON API requests.

    Converts gRPC and XML requests to an equivalent representation as a JSON request.

    TODO(#86) - this is used as a helper to treat some XML and gRPC requests as-if
        they where JSON requests, but seems like the work is incomplete.
    """

    protobuf_wrapper_to_json_args = {
        "if_generation_match": "ifGenerationMatch",
        "if_generation_not_match": "ifGenerationNotMatch",
        "if_metageneration_match": "ifMetagenerationMatch",
        "if_metageneration_not_match": "ifMetagenerationNotMatch",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def init_xml(cls, request):
        headers = {
            key.lower(): value
            for key, value in request.headers.items()
            if key.lower().startswith("x-goog-") or key.lower() == "range"
        }
        args = request.args.to_dict()
        args.update(cls.xml_headers_to_json_args(headers))
        return cls(args=args, headers=headers, environ=getattr(request, "environ", {}))

    @classmethod
    def xml_headers_to_json_args(cls, headers):
        field_map = {
            "x-goog-if-generation-match": "ifGenerationMatch",
            "x-goog-if-metageneration-match": "ifMetagenerationMatch",
            "x-goog-acl": "predefinedAcl",
        }
        args = {}
        for field_xml, field_json in field_map.items():
            if field_xml in headers:
                args[field_json] = headers[field_xml]
        return args

    _PREDEFINED_ACL_MAP = {
        storage_pb2.PredefinedObjectAcl.PREDEFINED_OBJECT_ACL_UNSPECIFIED: "",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_AUTHENTICATED_READ: "authenticatedREad",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_BUCKET_OWNER_FULL_CONTROL: "bucketOwnerFullControl",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_BUCKET_OWNER_READ: "bucketOwnerRead",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_PRIVATE: "private",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_PROJECT_PRIVATE: "projectPrivate",
        storage_pb2.PredefinedObjectAcl.OBJECT_ACL_PUBLIC_READ: "publicRead",
    }

    @classmethod
    def init_protobuf(cls, request, context):
        assert context is not None
        fake_request = FakeRequest(args={}, headers={})
        fake_request.update_protobuf(request, context)
        return fake_request

    def update_protobuf(self, request, context):
        assert context is not None
        for (
            proto_field,
            args_field,
        ) in FakeRequest.protobuf_wrapper_to_json_args.items():
            if hasattr(request, proto_field) and request.HasField(proto_field):
                self.args[args_field] = getattr(request, proto_field)
                setattr(self, proto_field, getattr(request, proto_field))
            else:
                setattr(self, proto_field, None)

        if hasattr(request, "generation"):
            self.args["generation"] = request.generation
            self.generation = request.generation
        else:
            self.generation = 0

        if hasattr(request, "predefined_acl"):
            self.args["predefinedAcl"] = FakeRequest._PREDEFINED_ACL_MAP[
                request.predefined_acl
            ]
            self.predefined_acl = request.predefined_acl
        else:
            self.predefined_acl = None

        csek_field = "common_object_request_params"
        if hasattr(request, csek_field):
            algorithm, key_b64, key_sha256_b64 = testbench.csek.extract(
                request, False, context
            )
            self.headers["x-goog-encryption-algorithm"] = algorithm
            self.headers["x-goog-encryption-key"] = key_b64
            self.headers["x-goog-encryption-key-sha256"] = key_sha256_b64
            setattr(self, csek_field, getattr(request, csek_field))
        else:
            setattr(
                self,
                csek_field,
                types.SimpleNamespace(
                    encryption_algorithm="",
                    encryption_key_bytes=b"",
                    encryption_key_sha256_bytes=b"",
                ),
            )

        if hasattr(request, "common_request_params"):
            self.common_request_params = request.common_request_params
            project = self.common_request_params.user_project
            if project.startswith("projects/"):
                project = project[len("projects/") :]
            self.args["userProject"] = project


# === REST === #


def nested_key(data):
    # This function take a dict and return a list of keys that works with `Scalpl` library.
    if isinstance(data, list):
        keys = []
        for i in range(len(data)):
            result = nested_key(data[i])
            if isinstance(result, list):
                if isinstance(data[i], dict):
                    keys.extend(["[%d].%s" % (i, item) for item in result])
                elif isinstance(data[i], list):
                    keys.extend(["[%d]%s" % (i, item) for item in result])
            keys.append("[%d]" % i)
        return keys
    elif isinstance(data, dict):
        keys = []
        for key, value in data.items():
            result = nested_key(value)
            if isinstance(result, list):
                if isinstance(value, dict):
                    keys.extend(["%s.%s" % (key, item) for item in result])
                elif isinstance(value, list):
                    keys.extend(["%s%s" % (key, item) for item in result])
            keys.append("%s" % key)
        return keys
    else:
        return []


def parse_fields(fields):
    # "kind,items(id,name)" -> ["kind", "items.id", "items.name"]
    res = []
    for i, c in enumerate(fields):
        if c != " " and c != ")":
            if c == "/":
                res.append(".")
            else:
                res.append(c)
        elif c == ")":
            childrens_fields = []
            tmp_field = []
            while res:
                if res[-1] != "," and res[-1] != "(":
                    tmp_field.append(res.pop())
                else:
                    childrens_fields.append(tmp_field)
                    tmp_field = []
                    if res.pop() == "(":
                        break
            parent_field = []
            while res and res[-1] != "," and res[-1] != "(":
                parent_field.append(res.pop())
            for i, field in enumerate(childrens_fields):
                res.extend(parent_field[::-1])
                res.append(".")
                while field:
                    res.append(field.pop())
                if i < len(childrens_fields) - 1:
                    res.append(",")
    return "".join(res).split(",")


def filter_response_rest(response, projection, fields):
    if fields is not None:
        fields = parse_fields(fields)
    keys_to_delete = set()
    if projection == "noAcl":
        keys_to_delete.add("owner")
        keys_to_delete.add("acl")
        keys_to_delete.add("defaultObjectAcl")
    for key in nested_key(response):
        simplfied_key = remove_index(key)
        if fields is not None:
            delete = True
            for field in fields:
                if field != "" and (
                    simplfied_key.startswith(field) or field.startswith(simplfied_key)
                ):
                    delete = False
                    break
            if delete:
                keys_to_delete.add(key)

    proxy = scalpl.Cut(response)
    for key in keys_to_delete:
        if proxy.get(key) is not None:
            del proxy[key]
    return proxy.data


def parse_multipart(request):
    content_type = request.headers.get("content-type")
    if content_type is None or not content_type.startswith("multipart/related"):
        testbench.error.invalid("Content-type header in multipart upload", None)
    _, _, boundary = content_type.partition("boundary=")
    if boundary is None:
        testbench.error.missing(
            "boundary in content-type header in multipart upload", None
        )

    body = extract_media(request)
    try:
        decoder = MultipartDecoder(body, content_type)
    except ImproperBodyPartContentException as e:
        testbench.error.invalid("Multipart body is malformed\n%s" % str(body), None)
    if len(decoder.parts) != 2:
        testbench.error.invalid("Multipart body is malformed\n%s" % str(body), None)
    resource = decoder.parts[0].text
    metadata = json.loads(resource)
    content_type_key = "content-type".encode("utf-8")
    headers = decoder.parts[1].headers
    content_type = {"content-type": headers[content_type_key].decode("utf-8")}
    media = decoder.parts[1].content
    return metadata, content_type, media


def extract_media(request):
    """Extract the media from a flask Request.

    To avoid race conditions when using greenlets we cannot perform I/O in the
    constructor of GcsObject, or in any of the operations that modify the state
    of the service.  Because sometimes the media is uploaded with chunked encoding,
    we need to do I/O before finishing the GcsObject creation. If we do this I/O
    after the GcsObject creation started, the the state of the application may change
    due to other I/O.

    :param request:flask.Request the HTTP request.
    :return: the full media of the request.
    :rtype: str
    """
    if request.environ.get("HTTP_TRANSFER_ENCODING", "") == "chunked":
        return request.environ.get("wsgi.input").read()
    return request.data


# === RESPONSE === #


def extract_projection(request, default, context):
    if context is not None:
        return default
    projection = request.args.get("projection")
    return projection if projection is not None else default


# === DATA === #


def corrupt_media(media):
    if not media:
        return bytearray(random.sample("abcdefghijklmnopqrstuvwxyz", 1), "utf-8")
    return b"B" + media[1:] if media[0:1] == b"A" else b"A" + media[1:]


# === HEADERS === #


def extract_instruction(request, context):
    instruction = None
    if context is not None:
        if hasattr(context, "invocation_metadata"):
            for key, value in context.invocation_metadata():
                if key == "x-goog-emulator-instructions":
                    instruction = value
    else:
        instruction = request.headers.get("x-goog-emulator-instructions")
        if instruction is None:
            instruction = request.headers.get("x-goog-testbench-instructions")
    return instruction


def enforce_patch_override(request):
    if (
        request.method == "POST"
        and request.headers.get("X-Http-Method-Override", "") != "PATCH"
    ):
        testbench.error.notallowed(context=None)


def _extract_data(data):
    if isinstance(data, flask.Response):
        return data.get_data()
    if isinstance(data, dict):
        return json.dumps(data)
    return data


def __get_streamer_response_fn(database, method, conn, test_id):
    def response_handler(data):
        def streamer():
            database.dequeue_next_instruction(test_id, method)
            d = _extract_data(data)
            chunk_size = 4
            for r in range(0, len(d), chunk_size):
                if r < 10:
                    chunk_end = min(r + chunk_size, len(d))
                    yield d[r:chunk_end]
                if conn is not None:
                    conn.close()
                # This exception is raised to abort the flow control. The
                # connection has already been closed, causing the client to
                # receive a "connection reset by peer" (or a similar error).
                # The exception is useful in unit tests (where there is no
                # socket to close), and stops the testbench from trying to
                # complete a request that we intentionally aborted.
                raise testbench.error.RestException(
                    "Injected 'connection reset by peer' fault", 500
                )

        return flask.Response(streamer())

    return response_handler


def __get_default_response_fn(data):
    return data


def __get_limit_response_fn(database, upload_id, test_id, method, limit):
    def limited_response_fn(data):
        upload = database.get_upload(upload_id, None)
        if upload.complete:
            database.dequeue_next_instruction(test_id, method)
            data = _extract_data(data)
            return flask.Response(
                data[0:limit], status=200, content_type="application/json"
            )
        else:
            return data

    return limited_response_fn


def handle_retry_test_instruction(database, request, method):
    upload_id = request.args.get("upload_id", None)
    test_id = request.headers.get("x-retry-test-id", None)
    if not test_id or not database.has_instructions_retry_test(test_id, method):
        return __get_default_response_fn
    next_instruction = database.peek_next_instruction(test_id, method)
    error_code_matches = testbench.common.retry_return_error_code.match(
        next_instruction
    )
    if error_code_matches:
        database.dequeue_next_instruction(test_id, method)
        items = list(error_code_matches.groups())
        error_code = items[0]
        error_message = {
            "error": {"message": "Retry Test: Caused a {}".format(error_code)}
        }
        testbench.error.generic(
            msg=error_message, rest_code=error_code, grpc_code=None, context=None
        )
    retry_connection_matches = testbench.common.retry_return_error_connection.match(
        next_instruction
    )
    if retry_connection_matches:
        items = list(retry_connection_matches.groups())
        if items[0] == "reset-connection":
            database.dequeue_next_instruction(test_id, method)
            fd = request.environ.get("gunicorn.socket", None)
            if fd is not None:
                fd.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
                fd.close()
            # This exception is raised to abort the flow control. The connection
            # has already been closed, causing the client to receive a "connection
            # reset by peer" (or a similar error). The exception is useful in
            # unit tests (where there is no socket to close), and stops the testbench
            # from trying to complete a request that we intentionally aborted.
            raise testbench.error.RestException(
                "Injected 'connection reset by peer' fault", 500
            )
        elif items[0] == "broken-stream":
            conn = request.environ.get("gunicorn.socket", None)
            return __get_streamer_response_fn(database, method, conn, test_id)
    error_after_bytes_matches = testbench.common.retry_return_error_after_bytes.match(
        next_instruction
    )
    if error_after_bytes_matches and method == "storage.objects.insert":
        items = list(error_after_bytes_matches.groups())
        error_code = int(items[0])
        after_bytes = int(items[1]) * 1024
        # Upload failures should allow to not complete after certain bytes
        upload_id = request.args.get("upload_id", None)
        if upload_id is not None:
            upload = database.get_upload(upload_id, None)
            if upload is not None and len(upload.media) >= after_bytes:
                database.dequeue_next_instruction(test_id, method)
                testbench.error.generic(
                    "Fault injected after uploading %d bytes" % len(upload.media),
                    rest_code=error_code,
                    grpc_code=StatusCode.INTERNAL,  # not really used
                    context=None,
                )
    retry_return_short_response = testbench.common.retry_return_short_response.match(
        next_instruction
    )
    if retry_return_short_response and method == "storage.objects.insert":
        upload_id = request.args.get("upload_id", None)
        if upload_id:
            items = list(retry_return_short_response.groups())
            with_bytes = int(items[0])
            return __get_limit_response_fn(
                database, upload_id, test_id, method, with_bytes
            )
    return __get_default_response_fn


def gen_retry_test_decorator(db):
    def retry_test(method):
        db.insert_supported_methods([method])

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                response_handler = handle_retry_test_instruction(
                    db, flask.request, method
                )
                return response_handler(func(*args, **kwargs))

            return wrapper

        return decorator

    return retry_test


def rest_crc32c_to_proto(crc32c):
    """Convert from the REST representation of crc32c checksums to the proto representation.

    REST uses base64 encoded 32-bit big endian integers, while protos use just `int32`.
    """
    return struct.unpack(">I", base64.b64decode(crc32c.encode("utf-8")))[0]


def rest_crc32c_from_proto(crc32c):
    """Convert from the gRPC/proto representation of crc32c checksums to the REST representation.

    REST uses base64 encoded 32-bit big endian integers, while protos use just `int32`.
    """
    return base64.b64encode(struct.pack(">I", crc32c)).decode("utf-8")


def rest_md5_to_proto(md5):
    """Convert the REST representation of MD5 hashes to the proto representation."""
    return base64.b64decode(md5)


def rest_md5_from_proto(md5):
    """Convert from the gRPC/proto representation of MD5 hashes to the REST representation."""
    return base64.b64encode(md5).decode("utf-8")


def rest_rfc3339_to_proto(rfc3339):
    """Convert a RFC3339 timestamp to the google.protobuf.Timestamp format."""
    ts = timestamp_pb2.Timestamp()
    ts.FromJsonString(rfc3339)
    return ts


def rest_adjust(data, adjustments):
    """
    Apply a per-key 'actions' to a dictionary *if* the key is present.

    When mapping between the gRPC and the REST representations of resources
    (Bucket, Object, etc.) we sometimes need to change the name and/or format
    of some fields.

    The `adjustments` describes what keys (if present) need adjustment, and
    a function that returns the new key and value for the item in `data`.

    Parameters
    ----------
    data : dict
        A dictionary, typically the REST representation of a resource
    adjustments : dict
        The keys in `data` that, if present, need adjustment. The values
        in this dictionary are functions returning a (key, value) tuple
        that replaces the existing tuple in `data`.

    Returns
    -------
    dict
        A copy of `data` with the changes prescribed by `adjustments`.
    """
    modified = data.copy()
    for key, action in adjustments.items():
        value = modified.pop(key, None)
        if value is not None:
            k, v = action(value)
            if k is not None:
                modified[k] = v
    return modified


def __preprocess_customer_encryption(rest):
    # json_format.ParseDict() automatically decodes bytes from
    # the base64 encoding, no need to manually doing so.
    return rest_adjust(rest, {"keySha256": lambda x: ("keySha256Bytes", x)})


def preprocess_object_metadata(metadata):
    """
    Convert from the JSON field names in an Object metadata to the storage/v2 field names.

    This function is used by both holder.py and object.py.
    """
    # For some fields the storage/v2 name just needs to change slightly.
    md = rest_adjust(
        metadata,
        {
            "kind": lambda x: (None, None),
            "id": lambda x: (None, None),
            "timeCreated": lambda x: ("createTime", x),
            "updated": lambda x: ("updateTime", x),
            "kmsKeyName": lambda x: ("kmsKey", x),
            "retentionExpirationTime": lambda x: ("retentionExpireTime", x),
            "timeDeleted": lambda x: ("deleteTime", x),
            "timeStorageClassUpdated": lambda x: ("updateStorageClassTime", x),
            "customerEncryption": lambda x: (
                "customerEncryption",
                __preprocess_customer_encryption(x),
            ),
        },
    )
    checksums = {}
    if "crc32c" in md:
        crc32c = md.pop("crc32c")
        if crc32c is not None:
            checksums["crc32c"] = rest_crc32c_to_proto(crc32c)
    if "md5Hash" in metadata:
        # Do not need to base64-encode here because the `json_format`
        # conversions already does that for bytes
        md5Hash = md.pop("md5Hash")
        if md5Hash is not None:
            checksums["md5Hash"] = md5Hash
    if len(checksums) > 0:
        md["checksums"] = checksums
    # Finally the ACLs, if present, have fewer fields in gRPC, remove
    # them if present, ignore then otherwise
    if "acl" in md:
        for a in md["acl"]:
            for field in ["kind", "bucket", "object", "generation"]:
                a.pop(field, None)
    return md


def rest_patch(target: dict, patch: dict, path: list = None) -> dict:
    """
    Applies a REST-style patch to a target dictionary.

    REST patches are more complicated than a simple `dict.update()`. Any `None` values
    delete a key, and the changes need to be applied recursively.

    :param target: the REST resource (in dict form) to be patched
    :param patch: the changes to be applied
    :param path: the path where this patch is being applied, used to report better errors.
    """
    if path is None:
        path = []
    patched = target.copy()
    for key, subpatch in patch.items():
        if subpatch is None:
            patched.pop(key, None)
            continue
        location = path + [key]
        if key not in patched:
            if isinstance(subpatch, dict):
                patched[key] = rest_patch({}, subpatch, location)
            else:
                patched[key] = subpatch
            continue
        subtarget = patched.get(key)
        if isinstance(subtarget, dict) and isinstance(subpatch, dict):
            patched[key] = rest_patch(subtarget, subpatch, location)
        elif isinstance(subtarget, dict) == isinstance(subpatch, dict):
            # Both `isinstance()` are equal, but not both true, so both
            # are false and we can handle this with a simple assignment.
            patched[key] = subpatch
        else:
            raise Exception("Type mismatch at %s" % ".".join(location))
    return patched


def bucket_name_from_proto(bucket_name):
    if bucket_name is None:
        return None
    prefix = "projects/_/buckets/"
    if bucket_name.startswith(prefix):
        return bucket_name[len(prefix) :]
    return bucket_name[:]


def bucket_name_to_proto(bucket_name):
    return "projects/_/buckets/" + bucket_name
