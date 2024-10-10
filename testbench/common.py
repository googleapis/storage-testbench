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
import gzip
import io
import json
import platform
import random
import re
import socket
import struct
import time
import types
from functools import wraps

import flask
import scalpl
from google.protobuf import timestamp_pb2
from grpc import StatusCode
from requests_toolbelt import MultipartDecoder
from requests_toolbelt.multipart.decoder import ImproperBodyPartContentException

import testbench
from google.storage.v2 import storage_pb2

re_remove_index = re.compile(r"\[\d+\]+|^[0-9]+")
retry_return_error_code = re.compile(r"return-([0-9]+)$")
retry_return_error_connection = re.compile(r"return-([a-z\-]+)$")
retry_return_error_after_bytes = re.compile(r"return-([0-9]+)-after-([0-9]+)K$")
retry_return_short_response = re.compile(
    r"return-broken-stream-final-chunk-after-([0-9]+)B$"
)
retry_return_broken_stream_after_bytes = re.compile(
    r"return-broken-stream-after-([0-9]+)K$"
)
retry_stall_after_bytes = re.compile(r"stall-for-([0-9]+)s-after-([0-9]+)K$")

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

    _COMMON_HEADERS = {
        "range",
        "accept-encoding",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def init_xml(cls, request):
        # Copy any common headers or starting with `x-goog-`
        headers = {
            key.lower(): value
            for key, value in request.headers.items()
            if key.lower().startswith("x-goog-") or key.lower() in cls._COMMON_HEADERS
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
            self.args["predefinedAcl"] = request.predefined_acl
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

        metadata = context.invocation_metadata()
        if "x-goog-user-project" in metadata:
            project = metadata["x-goog-user-project"]
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


def make_json_preconditions(request, prefix="if"):
    """Create the pre-conditions for most JSON requests.

    The prefix parameter can be `if` or `ifSource` to handle the special names
    used for source pre-conditions in `Objects: copy` and `Objects: rewrite`.
    """

    def if_metageneration_match(blob, _, ctx):
        match = request.args.get(prefix + "MetagenerationMatch", None)
        assert match is not None
        actual = blob.metadata.metageneration if blob is not None else 0
        if int(match) == 0 and blob is None:
            return True
        if int(match) != 0 and int(match) == actual:
            return True
        return testbench.error.mismatch(
            prefix + "MetagenerationMatch",
            expect=match,
            actual=blob.metadata.metageneration,
            context=ctx,
        )

    def if_metageneration_not_match(blob, _, ctx):
        match = request.args.get(prefix + "MetagenerationNotMatch", None)
        assert match is not None
        actual = blob.metadata.metageneration if blob is not None else 0
        if int(match) == 0 and blob is not None:
            return True
        if int(match) != 0 and int(match) != actual:
            return True
        return testbench.error.notchanged(
            prefix
            + "MetagenerationNotMatch expected %s == actual %s" % (match, actual),
            context=ctx,
        )

    def if_generation_match(_, live_generation, ctx):
        match = request.args.get(prefix + "GenerationMatch", None)
        assert match is not None
        if int(match) == 0 and (live_generation is None or live_generation == 0):
            return True
        if int(match) != 0 and int(match) == live_generation:
            return True
        return testbench.error.mismatch(
            prefix + "GenerationMatch",
            expect=match,
            actual=live_generation,
            context=ctx,
        )

    def if_generation_not_match(_, live_generation, ctx):
        match = request.args.get(prefix + "GenerationNotMatch", None)
        assert match is not None
        if int(match) == 0 and (live_generation is not None and live_generation != 0):
            return True
        if int(match) != 0 and int(match) != live_generation:
            return True
        return testbench.error.notchanged(
            prefix
            + "GenerationNotMatch expected %s == actual %s" % (match, live_generation),
            context=ctx,
        )

    args = {
        prefix + "MetagenerationMatch": if_metageneration_match,
        prefix + "MetagenerationNotMatch": if_metageneration_not_match,
        prefix + "GenerationMatch": if_generation_match,
        prefix + "GenerationNotMatch": if_generation_not_match,
    }
    preconditions = []
    for arg, predicate in args.items():
        if arg in request.args:
            preconditions.append(predicate)
    return preconditions


def make_xml_preconditions(request):
    """Create the pre-conditions for most XML requests."""

    def if_metageneration_match(blob, _, ctx):
        match = request.headers.get("x-goog-if-metageneration-match")
        assert match is not None
        actual = blob.metadata.metageneration if blob is not None else 0
        if int(match) == 0 and blob is None:
            return True
        if int(match) != 0 and int(match) == actual:
            return True
        return testbench.error.mismatch(
            "x-goog-if-metageneration-match",
            expect=match,
            actual=actual,
            context=ctx,
        )

    def if_generation_match(_, live_generation, ctx):
        match = request.headers.get("x-goog-if-generation-match")
        assert match is not None
        if int(match) == 0 and live_generation is None:
            return True
        if int(match) != 0 and int(match) == live_generation:
            return True
        return testbench.error.mismatch(
            "x-goog-if-generation-match",
            expect=match,
            actual=live_generation,
            context=ctx,
        )

    HEADERS = {
        "x-goog-if-metageneration-match": if_metageneration_match,
        "x-goog-if-generation-match": if_generation_match,
    }
    preconditions = []
    for arg, predicate in HEADERS.items():
        if arg in request.headers:
            preconditions.append(predicate)
    return preconditions


def make_grpc_preconditions(request, prefix="if_"):
    """Create the pre-conditions for most gRPC requests."""

    def if_metageneration_match(blob, _, ctx):
        assert request.HasField(prefix + "metageneration_match")
        match = getattr(request, prefix + "metageneration_match")
        if match == 0 and blob is None:
            return True
        actual = blob.metadata.metageneration if blob is not None else 0
        if match != 0 and match == actual:
            return True
        return testbench.error.mismatch(
            prefix + "if_metageneration_match",
            expect=match,
            actual=actual,
            context=ctx,
        )

    def if_metageneration_not_match(blob, _, ctx):
        assert request.HasField(prefix + "metageneration_not_match")
        match = getattr(request, prefix + "metageneration_not_match")
        if match == 0 and blob is not None:
            return True
        actual = blob.metadata.metageneration if blob is not None else 0
        if match != 0 and match != actual:
            return True
        return testbench.error.notchanged(
            prefix
            + "metageneration_not_match expected %s == actual %s" % (match, actual),
            context=ctx,
        )

    def if_generation_match(_, live_generation, ctx):
        assert request.HasField(prefix + "generation_match")
        match = getattr(request, prefix + "generation_match")
        if match == 0 and live_generation is None:
            return True
        if match != 0 and match == live_generation:
            return True
        return testbench.error.mismatch(
            prefix + "generation_match",
            expect=match,
            actual=live_generation,
            context=ctx,
        )

    def if_generation_not_match(_, live_generation, ctx):
        assert request.HasField(prefix + "generation_not_match")
        match = getattr(request, prefix + "generation_not_match")
        if match == 0 and live_generation is not None:
            return True
        if match != 0 and match != live_generation:
            return True
        return testbench.error.notchanged(
            prefix
            + "generation_not_match expected %s == actual %s"
            % (match, live_generation),
            context=ctx,
        )

    preconditions = []
    fields = {
        prefix + "metageneration_match": if_metageneration_match,
        prefix + "metageneration_not_match": if_metageneration_not_match,
        prefix + "generation_match": if_generation_match,
        prefix + "generation_not_match": if_generation_not_match,
    }
    for field, predicate in fields.items():
        if hasattr(request, field) and request.HasField(field):
            preconditions.append(predicate)
    return preconditions


def make_json_bucket_preconditions(request):
    """Create the pre-conditions for most JSON Bucket-related requests."""

    def if_metageneration_match(bucket, ctx):
        match = request.args.get("ifMetagenerationMatch", None)
        assert match is not None
        actual = bucket.metadata.metageneration if bucket is not None else 0
        if int(match) == 0 and bucket is None:
            return True
        if int(match) != 0 and int(match) == actual:
            return True
        return testbench.error.mismatch(
            "ifMetagenerationMatch",
            expect=match,
            actual=actual,
            context=ctx,
        )

    def if_metageneration_not_match(bucket, ctx):
        match = request.args.get("ifMetagenerationNotMatch", None)
        assert match is not None
        actual = bucket.metadata.metageneration if bucket is not None else 0
        if int(match) == 0 and bucket is not None:
            return True
        if int(match) != 0 and int(match) != actual:
            return True
        return testbench.error.notchanged(
            "ifMetagenerationNotMatch expected %s == actual %s" % (match, actual),
            context=ctx,
        )

    args = {
        "ifMetagenerationMatch": if_metageneration_match,
        "ifMetagenerationNotMatch": if_metageneration_not_match,
    }
    preconditions = []
    for arg, predicate in args.items():
        if arg in request.args:
            preconditions.append(predicate)
    return preconditions


def make_grpc_bucket_preconditions(request):
    """Create the pre-conditions for most gRPC requests."""

    def if_metageneration_match(bucket, ctx):
        assert request.HasField("if_metageneration_match")
        if request.if_metageneration_match == 0 and bucket is None:
            return True
        actual = bucket.metadata.metageneration if bucket is not None else 0
        if (
            request.if_metageneration_match != 0
            and request.if_metageneration_match == actual
        ):
            return True
        return testbench.error.mismatch(
            "if_metageneration_match",
            expect=request.if_metageneration_match,
            actual=actual,
            context=ctx,
        )

    def if_metageneration_not_match(bucket, ctx):
        assert request.HasField("if_metageneration_not_match")
        if request.if_metageneration_not_match == 0 and bucket is not None:
            return True
        actual = bucket.metadata.metageneration if bucket is not None else 0
        if (
            request.if_metageneration_not_match != 0
            and request.if_metageneration_not_match != actual
        ):
            return True
        return testbench.error.notchanged(
            "if_metageneration_not_match expected %s == actual %s"
            % (request.if_metageneration_not_match, actual),
            context=ctx,
        )

    preconditions = []
    fields = {
        "if_metageneration_match": if_metageneration_match,
        "if_metageneration_not_match": if_metageneration_not_match,
    }
    for field, predicate in fields.items():
        if hasattr(request, field) and request.HasField(field):
            preconditions.append(predicate)
    return preconditions


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


def partial_media(media, range_end, range_start=0):
    """Returns partial media due to forced interruption or server validation."""
    return media[range_start:range_end]


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


def _extract_headers(response):
    if isinstance(response, flask.Response):
        return response.headers
    return dict()


def _using_waitress(request):
    return request.environ.get("SERVER_SOFTWARE", "").startswith("waitress")


def _get_socket(request):
    if _using_waitress(request):
        channel = request.environ.get("waitress.channel", None)
        if channel is None:
            return None
        return channel.socket
    return request.environ.get("gunicorn.socket", None)


def _make_closer(request):
    def _null_closer():
        pass

    if _using_waitress(request):
        channel = request.environ.get("waitress.channel", None)

        def _closer():
            channel.close()

        return _null_closer if channel is None else _closer
    socket = request.environ.get("gunicorn.socket", None)

    def _closer():
        socket.close()

    return _null_closer if socket is None else _closer


def __get_streamer_response_fn(
    database, method, socket_closer, test_id, limit=4, chunk_size=4
):
    def response_handler(data):
        def streamer():
            d = _extract_data(data)
            bytes_yield = 0
            for r in range(0, len(d), chunk_size):
                if bytes_yield < limit:
                    chunk_end = min(r + chunk_size, len(d))
                    chunk_downloaded = chunk_end - r
                    bytes_yield += chunk_downloaded
                    yield d[r:chunk_end]
                if bytes_yield >= limit:
                    database.dequeue_next_instruction(test_id, method)
                    socket_closer()
                    # This exception is raised to abort the flow control. The
                    # connection has already been closed, causing the client to
                    # receive a "broken stream" or "connection reset by peer" error.
                    # The exception is useful in unit tests (where there is no
                    # socket to close), and stops the testbench from trying to
                    # complete a request that we intentionally aborted.
                    raise testbench.error.RestException(
                        "Injected 'broken stream' fault", 500
                    )

        return flask.Response(streamer(), headers=_extract_headers(data))

    return response_handler


def __get_stream_and_stall_fn(
    database, method, test_id, limit=4, stall_time_sec=10, chunk_size=4
):
    def response_handler(data):
        def streamer():
            d = _extract_data(data)
            bytes_yield = 0
            instruction_dequed = False
            for r in range(0, len(d), chunk_size):
                if bytes_yield >= limit and not instruction_dequed:
                    time.sleep(stall_time_sec)
                    database.dequeue_next_instruction(test_id, method)
                    instruction_dequed = True
                chunk_end = min(r + chunk_size, len(d))
                chunk_downloaded = chunk_end - r
                bytes_yield += chunk_downloaded
                yield d[r:chunk_end]

        return flask.Response(streamer(), headers=_extract_headers(data))

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


def grpc_handle_retry_test_instruction(database, request, context, method):
    test_id = get_retry_test_id_from_context(context)
    # Validate retry instructions, method and request transport.
    if not test_id or not database.has_instructions_retry_test(
        test_id, method, transport="GRPC"
    ):
        return __get_default_response_fn
    next_instruction = database.peek_next_instruction(test_id, method)
    error_code_matches = testbench.common.retry_return_error_code.match(
        next_instruction
    )
    if error_code_matches:
        database.dequeue_next_instruction(test_id, method)
        items = list(error_code_matches.groups())
        rest_code = items[0]
        grpc_code = _grpc_forced_failure_from_http_instruction(rest_code)
        msg = {"error": {"message": "Retry Test: Caused a {}".format(grpc_code)}}
        testbench.error.inject_error(context, rest_code, grpc_code, msg=msg)
    retry_connection_matches = testbench.common.retry_return_error_connection.match(
        next_instruction
    )
    if retry_connection_matches:
        items = list(retry_connection_matches.groups())
        if items[0] == "reset-connection":
            database.dequeue_next_instruction(test_id, method)
            context.abort(
                StatusCode.UNAVAILABLE,
                "Injected 'socket closed, connection reset by peer' fault",
            )
    return __get_default_response_fn


def handle_retry_test_instruction(database, request, socket_closer, method):
    upload_id = request.args.get("upload_id", None)
    test_id = request.headers.get("x-retry-test-id", None)
    # Validate retry instructions, method and request transport.
    if not test_id or not database.has_instructions_retry_test(
        test_id, method, transport="HTTP"
    ):
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
            sock = _get_socket(request)
            if sock is not None:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
                socket_closer()

            # This exception is raised to abort the flow control. The connection
            # has already been closed, causing the client to receive a "connection
            # reset by peer" (or a similar error). The exception is useful in
            # unit tests (where there is no socket to close), and stops the testbench
            # from trying to complete a request that we intentionally aborted.
            raise testbench.error.RestException(
                "Injected 'connection reset by peer' fault", 500
            )
        elif items[0] == "broken-stream":
            return __get_streamer_response_fn(database, method, socket_closer, test_id)
    broken_stream_after_bytes = (
        testbench.common.retry_return_broken_stream_after_bytes.match(next_instruction)
    )
    if broken_stream_after_bytes and method == "storage.objects.get":
        items = list(broken_stream_after_bytes.groups())
        after_bytes = int(items[0]) * 1024
        return __get_streamer_response_fn(
            database, method, socket_closer, test_id, limit=after_bytes
        )

    retry_stall_after_bytes_matches = testbench.common.retry_stall_after_bytes.match(
        next_instruction
    )
    if retry_stall_after_bytes_matches and method == "storage.objects.get":
        items = list(retry_stall_after_bytes_matches.groups())
        stall_time = int(items[0])
        after_bytes = int(items[1]) * 1024
        return __get_stream_and_stall_fn(
            database, method, test_id, limit=after_bytes, stall_time_sec=stall_time
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
                    db, flask.request, _make_closer(flask.request), method
                )
                return response_handler(func(*args, **kwargs))

            return wrapper

        return decorator

    return retry_test

def get_stall_uploads_after_bytes(
    database, request, context=None, transport="HTTP"
):
    """Retrieve error code and #bytes corresponding to uploads from retry test instructions."""
    method = "storage.objects.insert"
    if context is not None:
        test_id = get_retry_test_id_from_context(context)
    else:
        test_id = request.headers.get("x-retry-test-id", None)
    if not test_id:
        return 0, 0, ""
    next_instruction = None
    if database.has_instructions_retry_test(test_id, method, transport=transport):
        next_instruction = database.peek_next_instruction(test_id, method)
    if not next_instruction:
        return 0, 0, ""

    stall_after_byte_matches = testbench.common.retry_stall_after_bytes.match(
        next_instruction
    )
    if stall_after_byte_matches:
        items = list(stall_after_byte_matches.groups())
        stall_time = int(items[0])
        after_bytes = int(items[1]) * 1024
        return stall_time, after_bytes, test_id

    return 0, 0, ""

def get_retry_uploads_error_after_bytes(
    database, request, context=None, transport="HTTP"
):
    """Retrieve error code and #bytes corresponding to uploads from retry test instructions."""
    method = "storage.objects.insert"
    if context is not None:
        test_id = get_retry_test_id_from_context(context)
    else:
        test_id = request.headers.get("x-retry-test-id", None)
    if not test_id:
        return 0, 0, ""
    next_instruction = None
    if database.has_instructions_retry_test(test_id, method, transport=transport):
        next_instruction = database.peek_next_instruction(test_id, method)
    if not next_instruction:
        return 0, 0, ""
    error_after_bytes_matches = testbench.common.retry_return_error_after_bytes.match(
        next_instruction
    )
    if error_after_bytes_matches:
        items = list(error_after_bytes_matches.groups())
        error_code = int(items[0])
        after_bytes = int(items[1]) * 1024
        return error_code, after_bytes, test_id

    return 0, 0, ""

def handle_stall_uploads_after_bytes(
    upload,
    data,
    database,
    stall_time,
    after_bytes,
    last_byte_persisted,
    chunk_first_byte,
    chunk_last_byte,
    test_id=0,
):
    """
    Handle stall-after-bytes instructions for resumable uploads and commit only partial data before forcing a testbench error.
    This helper method also ignores request bytes that have already been persisted, which aligns with GCS behavior.
    """
    if after_bytes > last_byte_persisted and after_bytes <= (chunk_last_byte + 1):
        range_start = 0
        # Ignore request bytes that have already been persisted.
        if last_byte_persisted != 0 and int(chunk_first_byte) <= last_byte_persisted:
            range_start = last_byte_persisted - int(chunk_first_byte) + 1
        range_end = len(data)
        # Only partial data will be commited due to the instructed interruption.
        if after_bytes <= chunk_last_byte:
            range_end = len(data) - (chunk_last_byte - after_bytes + 1)
        data = testbench.common.partial_media(
            data, range_end=range_end, range_start=range_start
        )
        upload.media += data
        upload.complete = False

    if len(upload.media) >= after_bytes:
        print("Upload data: ", after_bytes)
        print("Stall time: ", stall_time)
        if test_id:
            database.dequeue_next_instruction(test_id, "storage.objects.insert")
        time.sleep(stall_time)

def handle_retry_uploads_error_after_bytes(
    upload,
    data,
    database,
    error_code,
    after_bytes,
    last_byte_persisted,
    chunk_first_byte,
    chunk_last_byte,
    test_id=0,
):
    """
    Handle error-after-bytes instructions for resumable uploads and commit only partial data before forcing a testbench error.
    This helper method also ignores request bytes that have already been persisted, which aligns with GCS behavior.
    """
    if after_bytes > last_byte_persisted and after_bytes <= (chunk_last_byte + 1):
        range_start = 0
        # Ignore request bytes that have already been persisted.
        if last_byte_persisted != 0 and int(chunk_first_byte) <= last_byte_persisted:
            range_start = last_byte_persisted - int(chunk_first_byte) + 1
        range_end = len(data)
        # Only partial data will be commited due to the instructed interruption.
        if after_bytes <= chunk_last_byte:
            range_end = len(data) - (chunk_last_byte - after_bytes + 1)
        data = testbench.common.partial_media(
            data, range_end=range_end, range_start=range_start
        )
        upload.media += data
        upload.complete = False
    if len(upload.media) >= after_bytes:
        if test_id:
            database.dequeue_next_instruction(test_id, "storage.objects.insert")
        testbench.error.generic(
            "Fault injected during a resumable upload",
            rest_code=error_code,
            grpc_code=None,
            context=None,
        )


def handle_grpc_retry_uploads_error_after_bytes(
    context,
    upload,
    data,
    database,
    rest_code,
    after_bytes,
    write_offset,
    persisted_size,
    expected_persisted_size,
    test_id,
):
    """
    Handle error-after-bytes instructions for resumable uploads in the grpc server and commit only partial data before forcing a testbench error.
    This helper method also ignores request bytes that have already been persisted, which aligns with GCS behavior.
    """
    if after_bytes > len(upload.media) and after_bytes <= expected_persisted_size:
        # Ignore request bytes that have already been persisted.
        range_start = 0
        if len(upload.media) != 0 and write_offset < persisted_size:
            range_start = persisted_size - write_offset
        # Only partial data will be commited due to the instructed interruption.
        range_end = range_start + (after_bytes - len(upload.media))
        content = testbench.common.partial_media(
            data, range_end=range_end, range_start=range_start
        )
        upload.media += content
        database.dequeue_next_instruction(test_id, "storage.objects.insert")
        grpc_code = _grpc_forced_failure_from_http_instruction(str(rest_code))
        msg = {"error": {"message": "Retry Test: Caused a {}".format(grpc_code)}}
        testbench.error.inject_error(context, rest_code, grpc_code, msg=msg)


def get_retry_test_id_from_context(context):
    """Get the retry test id from context; returns None if not found."""
    if context is not None:
        if hasattr(context, "invocation_metadata") and isinstance(
            context.invocation_metadata(), tuple  # Handle mocks in tests
        ):
            for key, value in context.invocation_metadata():
                if key == "x-retry-test-id":
                    return value


def get_broken_stream_after_bytes(instruction):
    """Get after_bytes for return-broken-stream retry instructions; returns 0 if instructions do not apply."""
    after_bytes = 0
    retry_connection_matches = testbench.common.retry_return_error_connection.match(
        instruction
    )
    if (
        retry_connection_matches
        and list(retry_connection_matches.groups())[0] == "broken-stream"
    ):
        after_bytes = 4
    broken_stream_after_bytes = (
        testbench.common.retry_return_broken_stream_after_bytes.match(instruction)
    )
    if broken_stream_after_bytes:
        items = list(broken_stream_after_bytes.groups())
        after_bytes = int(items[0]) * 1024
    return after_bytes


def handle_gzip_request(request):
    """
    Handle gzip compressed JSON payloads when Content-Encoding: gzip is present on metadata requests.
    No decompressions for media uploads when object's metadata includes Content-Encoding: gzip.
    """
    if (
        request.headers.get("Content-Encoding", None) == "gzip"
        and request.args.get("contentEncoding", None) != "gzip"
    ):
        request.data = gzip.decompress(request.data)
        request.environ["wsgi.input"] = io.BytesIO(request.data)


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

    This function is used by both upload.py and object.py.
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
            for field in ["kind", "bucket", "object", "generation", "etag"]:
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


def _grpc_forced_failure_from_http_instruction(http_code):
    # For Retry Test API and retry conformance tests internal use only.
    # Convert http retry instructions to the closest grpc forced failure.
    # Only map the status codes that are used in tests and listed in
    # the README, to avoid error-prone code conversions.
    status_map = {
        "400": StatusCode.INVALID_ARGUMENT,
        "401": StatusCode.UNAUTHENTICATED,
        "408": StatusCode.UNAVAILABLE,  # TODO: Unresolved discussion on 408 equivalent, see b/282880909
        "429": StatusCode.RESOURCE_EXHAUSTED,
        "500": StatusCode.INTERNAL,
        "503": StatusCode.UNAVAILABLE,
        "504": StatusCode.DEADLINE_EXCEEDED,
    }
    return status_map.get(http_code, None)
