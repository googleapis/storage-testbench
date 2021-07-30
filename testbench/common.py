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

import re
import types
from flask import Response as FlaskResponse

re_remove_index = re.compile(r"\[\d+\]+|^[0-9]+")
retry_return_error_code = re.compile(r"return-([0-9]+)$")
retry_return_error_connection = re.compile(r"return-([a-z\-]+)$")
retry_return_error_after_bytes = re.compile(r"return-([0-9]+)-after-([0-9]+)K$")
content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+|[0-9]+-\*)\/(\*|[0-9]+)")

# === STR === #


re_snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def to_snake_case(string):
    return re_snake_case.sub("_", string).lower()


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
