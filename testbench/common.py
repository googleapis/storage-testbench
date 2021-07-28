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
import json
import random
import re
import types
import sys
import socket
import struct
from flask import Response as FlaskResponse

import scalpl
import testbench

from google.protobuf import timestamp_pb2
from requests_toolbelt import MultipartDecoder
from requests_toolbelt.multipart.decoder import ImproperBodyPartContentException

re_remove_index = re.compile(r"\[\d+\]+|^[0-9]+")
retry_return_error_code = re.compile(r"return-([0-9]+)$")
retry_return_error_connection = re.compile(r"return-([a-z\-]+)$")
retry_return_error_after_bytes = re.compile(r"return-([0-9]+)-after-([0-9]+)K$")
content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+|[0-9]+-\*)\/(\*|[0-9]+)")

# === STR === #


re_snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def to_snake_case(string):
    return re_snake_case.sub("_", string).lower()


def remove_index(string):
    return re_remove_index.sub("", string)


# === FAKE REQUEST === #


class FakeRequest(types.SimpleNamespace):
    protobuf_wrapper_to_json_args = {
        "if_generation_match": "ifGenerationMatch",
        "if_generation_not_match": "ifGenerationNotMatch",
        "if_metageneration_match": "ifMetagenerationMatch",
        "if_metageneration_not_match": "ifMetagenerationNotMatch",
        "if_source_generation_match": "ifSourceGenerationMatch",
        "if_source_generation_not_match": "ifSourceGenerationNotMatch",
        "if_source_metageneration_match": "ifSourceMetagenerationMatch",
        "if_source_metageneration_not_match": "ifSourceMetagenerationNotMatch",
    }

    protobuf_scalar_to_json_args = {
        "predefined_acl": "predefinedAcl",
        "destination_predefined_acl": "destinationPredefinedAcl",
        "generation": "generation",
        "source_generation": "sourceGeneration",
        "projection": "projection",
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
        return cls(args=args, headers=headers)

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

    def HasField(self, field):
        return hasattr(self, field) and getattr(self, field) is not None

    @classmethod
    def init_protobuf(cls, request, context):
        fake_request = FakeRequest(args={}, headers={})
        fake_request.update_protobuf(request, context)
        return fake_request

    def update_protobuf(self, request, context):
        for (
            proto_field,
            args_field,
        ) in FakeRequest.protobuf_wrapper_to_json_args.items():
            if hasattr(request, proto_field) and request.HasField(proto_field):
                self.args[args_field] = getattr(request, proto_field).value
                setattr(self, proto_field, getattr(request, proto_field))
        for (
            proto_field,
            args_field,
        ) in FakeRequest.protobuf_scalar_to_json_args.items():
            if hasattr(request, proto_field):
                self.args[args_field] = getattr(request, proto_field)
                setattr(self, proto_field, getattr(request, proto_field))
        csek_field = "common_object_request_params"
        if hasattr(request, csek_field):
            algorithm, key_b64, key_sha256_b64 = testbench.csek.extract(
                request, False, context
            )
            self.headers["x-goog-encryption-algorithm"] = algorithm
            self.headers["x-goog-encryption-key"] = key_b64
            self.headers["x-goog-encryption-key-sha256"] = key_sha256_b64
            setattr(self, csek_field, getattr(request, csek_field))
        elif not hasattr(self, csek_field):
            setattr(
                self,
                csek_field,
                types.SimpleNamespace(
                    encryption_algorithm="", encryption_key="", encryption_key_sha256=""
                ),
            )
