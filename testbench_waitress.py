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

import socket

from waitress.adjustments import Adjustments
from waitress.task import ThreadedTaskDispatcher

from waitress.server import MultiSocketServer
from waitress.server import TcpWSGIServer
from waitress.channel import HTTPChannel
from waitress import profile
from waitress.task import WSGITask
import logging

if hasattr(socket, "AF_UNIX"):
    from waitress.server import UnixWSGIServer

# Functions in this script are duplicating some of the code of waitress module. For now it needs to be done
# becasue we needs request sockets of waitress to produce "broken-stream" and "return-reset-connection"
# error. If we are going to update waitress vesion in setup.py that code in this file also needs to be updated.


class testbench_WSGITask(WSGITask):
    def get_environment(self):
        environ = super().get_environment()
        environ["waitress.channel"] = self.channel
        return environ


class testbench_HTTPChannel(HTTPChannel):
    task_class = testbench_WSGITask


class testbench_TcpWSGIServer(TcpWSGIServer):
    channel_class = testbench_HTTPChannel


if hasattr(socket, "AF_UNIX"):

    class testbench_UnixWSGIServer(UnixWSGIServer):
        channel_class = testbench_HTTPChannel


def serve(app, **kw):
    _server = kw.pop("_server", testbench_create_server)  # test shim
    _quiet = kw.pop("_quiet", False)  # test shim
    _profile = kw.pop("_profile", False)  # test shim
    if not _quiet:  # pragma: no cover
        # idempotent if logging has already been set up
        logging.basicConfig()
    server = _server(app, **kw)
    if not _quiet:  # pragma: no cover
        server.print_listen("Serving on http://{}:{}")
    if _profile:  # pragma: no cover
        profile("server.run()", globals(), locals(), (), False)
    else:
        server.run()


def testbench_create_server(
    application, map=None, _start=True, _sock=None, _dispatcher=None, **kw
):
    """
    if __name__ == '__main__':
        server = create_server(app)
        server.run()
    """
    if application is None:
        raise ValueError(
            'The "app" passed to ``create_server`` was ``None``.  You forgot '
            "to return a WSGI app within your application."
        )
    adj = Adjustments(**kw)

    if map is None:  # pragma: nocover
        map = {}

    dispatcher = _dispatcher
    if dispatcher is None:
        dispatcher = ThreadedTaskDispatcher()
        dispatcher.set_thread_count(adj.threads)

    if adj.unix_socket and hasattr(socket, "AF_UNIX"):
        sockinfo = (socket.AF_UNIX, socket.SOCK_STREAM, None, None)
        return testbench_UnixWSGIServer(
            application,
            map,
            _start,
            _sock,
            dispatcher=dispatcher,
            adj=adj,
            sockinfo=sockinfo,
        )

    effective_listen = []
    last_serv = None
    if not adj.sockets:
        for sockinfo in adj.listen:
            # When TcpWSGIServer is called, it registers itself in the map. This
            # side-effect is all we need it for, so we don't store a reference to
            # or return it to the user.
            last_serv = testbench_TcpWSGIServer(
                application,
                map,
                _start,
                _sock,
                dispatcher=dispatcher,
                adj=adj,
                sockinfo=sockinfo,
            )
            effective_listen.append(
                (last_serv.effective_host, last_serv.effective_port)
            )

    for sock in adj.sockets:
        sockinfo = (sock.family, sock.type, sock.proto, sock.getsockname())
        if sock.family == socket.AF_INET or sock.family == socket.AF_INET6:
            last_serv = testbench_TcpWSGIServer(
                application,
                map,
                _start,
                sock,
                dispatcher=dispatcher,
                adj=adj,
                bind_socket=False,
                sockinfo=sockinfo,
            )
            effective_listen.append(
                (last_serv.effective_host, last_serv.effective_port)
            )
        elif hasattr(socket, "AF_UNIX") and sock.family == socket.AF_UNIX:
            last_serv = testbench_UnixWSGIServer(
                application,
                map,
                _start,
                sock,
                dispatcher=dispatcher,
                adj=adj,
                bind_socket=False,
                sockinfo=sockinfo,
            )
            effective_listen.append(
                (last_serv.effective_host, last_serv.effective_port)
            )

    # We are running a single server, so we can just return the last server,
    # saves us from having to create one more object
    if len(effective_listen) == 1:
        # In this case we have no need to use a MultiSocketServer
        return last_serv

    log_info = last_serv.log_info
    # Return a class that has a utility function to print out the sockets it's
    # listening on, and has a .run() function. All of the TcpWSGIServers
    # registered themselves in the map above.
    return MultiSocketServer(map, adj, effective_listen, dispatcher, log_info)
