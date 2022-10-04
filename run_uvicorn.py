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

import sys
import os

sys.path.append(
    os.path.abspath("C:\\Users\\anuraags\\gcp\\storage-testbench\\google\\iam\\v1")
)
sys.path.append(
    os.path.abspath("C:\\Users\\anuraags\\gcp\\storage-testbench\\google\\storage\\v2")
)

import asyncio
import socket
import sys
from uvicorn import Config, Server
from typing import Sequence
from uvicorn_socket import setsocket


class decorated_server(Server):
    def _log_started_message(self, listeners: Sequence[socket.SocketType]) -> None:
        setsocket(listeners[0])
        super()._log_started_message(listeners)


if len(sys.argv) == 3:
    sock_host = sys.argv[1]
    sock_port = int(sys.argv[2])
    sys.argv.clear()

    async def main():
        print("1")
        config = Config("testbench:run", host=sock_host, port=sock_port, reload=True)
        server = decorated_server(config)
        await server.serve()

    asyncio.run(main())

else:
    print("Please provide <hostname> and <port>")
