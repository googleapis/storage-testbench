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

# from asyncore import socket_map
# from logging.handlers import SocketHandler

# sys.path.append(os.path.abspath("C:\\Users\\anuraags\\gcp\\storage-testbench\\google\\iam\\v1"))
# sys.path.append(os.path.abspath("C:\\Users\\anuraags\\gcp\\storage-testbench\\google\\storage\\v2"))

# import asyncio
# import socket
# import sys
# import functools
# import platform
# from uvicorn import Config, Server
# from typing import Sequence
# from uvicorn_socket import setsocket

# class decorated_server(Server):
#     def _log_started_message(self, listeners: Sequence[socket.SocketType]) -> None:
#         print(listeners[1])
#         setsocket(listeners[1])
#         print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
#         super()._log_started_message(listeners)

#     async def startup(self, sockets: list = None) -> None:
#         await self.lifespan.startup()
#         if self.lifespan.should_exit:
#             self.should_exit = True
#             return

#         config = self.config

#         create_protocol = functools.partial(
#             config.http_protocol_class, config=config, server_state=self.server_state
#         )
#         loop = asyncio.get_running_loop()

#         listeners: Sequence[socket.SocketType]
#         if sockets is not None:
#             # Explicitly passed a list of open sockets.
#             # We use this when the server is run from a Gunicorn worker.

#             def _share_socket(sock: socket.SocketType) -> socket.SocketType:
#                 # Windows requires the socket be explicitly shared across
#                 # multiple workers (processes).
#                 from socket import fromshare  # type: ignore

#                 sock_data = sock.share(os.getpid())  # type: ignore
#                 return fromshare(sock_data)

#             self.servers = []
#             for sock in sockets:
#                 if config.workers > 1 and platform.system() == "Windows":
#                     sock = _share_socket(sock)
#                 server = await loop.create_server(
#                     create_protocol, sock=sock, ssl=config.ssl, backlog=config.backlog
#                 )
#                 self.servers.append(server)
#             listeners = sockets

#         elif config.fd is not None:
#             # Use an existing socket, from a file descriptor.
#             sock = socket.fromfd(config.fd, socket.AF_UNIX, socket.SOCK_STREAM)
#             server = await loop.create_server(
#                 create_protocol, sock=sock, ssl=config.ssl, backlog=config.backlog
#             )
#             assert server.sockets is not None  # mypy
#             listeners = server.sockets
#             self.servers = [server]

#         elif config.uds is not None:
#             # Create a socket using UNIX domain socket.
#             uds_perms = 0o666
#             if os.path.exists(config.uds):
#                 uds_perms = os.stat(config.uds).st_mode
#             server = await loop.create_unix_server(
#                 create_protocol, path=config.uds, ssl=config.ssl, backlog=config.backlog
#             )
#             os.chmod(config.uds, uds_perms)
#             assert server.sockets is not None  # mypy
#             listeners = server.sockets
#             self.servers = [server]

#         else:
#             # Standard case. Create a socket from a host/port pair.
#             try:
#                 server = await loop.create_server(
#                     create_protocol,
#                     host=config.host,
#                     port=config.port,
#                     ssl=config.ssl,
#                     backlog=config.backlog,
#                 )
#             except OSError as exc:
#                 logger.error(exc)
#                 await self.lifespan.shutdown()
#                 sys.exit(1)

#             assert server.sockets is not None
#             listeners = server.sockets
#             self.servers = [server]

#         if sockets is None:
#             self._log_started_message(listeners)
#         else:
#             # We're most likely running multiple workers, so a message has already been
#             # logged by `config.bind_socket()`.
#             pass

#         self.started = True

# class decorated_config(Config):
#     def bind_socket(self) -> socket.socket:
#         print("************************Yo Bro*************************************")
#         return super().bind_socket()


# if len(sys.argv) == 3:
#     sock_host = sys.argv[1]
#     sock_port = int(sys.argv[2])
#     sys.argv.clear()

#     async def main():
#         print("1")
#         config = decorated_config("testbench:run", host=sock_host, port=sock_port, reload=True)
#         server = decorated_server(config)
#         await server.serve()

#     asyncio.run(main())

# else:
#     print("Please provide <hostname> and <port>")

#waitress-serve --listen=localhost:9000 testbench:run

import testbench_waitress
import testbench

testbench_waitress.serve(testbench.run, listen='localhost:9000')