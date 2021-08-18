#!/usr/bin/env python3
#
# Copyright 2021 Google LLC
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

"""Helper function to test multipart uploads."""

import json


def format_multipart_upload(metadata, media, content_type="application/octet-stream"):
    boundary = "test_separator_deadbeef"
    payload = (
        ("--" + boundary + "\r\n").join(
            [
                "",
                # object metadata "part"
                "\r\n".join(
                    [
                        "Content-Type: application/json; charset=UTF-8",
                        "",
                        json.dumps(metadata),
                        "",
                    ]
                ),
                # object media "part"
                "\r\n".join(
                    [
                        "Content-Type: " + content_type,
                        "Content-Length: %d" % len(media),
                        "",
                        media,
                        "",
                    ]
                ),
            ]
        )
        + "--"
        + boundary
        + "--\r\n"
    )
    return boundary, payload
