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

"""Request's HTTPChannel with socket of waitress is exposed to produce "broken-stream" and "return-reset-connection" error."""

from waitress import create_server
from waitress.channel import HTTPChannel
from waitress.task import WSGITask


class testbench_WSGITask(WSGITask):
    def get_environment(self):
        environ = super().get_environment()
        environ["waitress.channel"] = self.channel
        return environ


class testbench_HTTPChannel(HTTPChannel):
    task_class = testbench_WSGITask


def testbench_create_server(
    application, map=None, _start=True, _sock=None, _dispatcher=None, **kw
):
    # This check is only intended to support testing of values populated in the map.
    if map is None:
        map = {}
    server = create_server(
        application=application,
        map=map,
        _start=_start,
        _sock=_sock,
        _dispatcher=_dispatcher,
        **kw
    )

    for key in map:
        if (
            map[key].__class__.__name__ == "TcpWSGIServer"
            or map[key].__class__.__name__ == "UnixWSGIServer"
        ):
            map[key].channel_class = testbench_HTTPChannel

    return server
