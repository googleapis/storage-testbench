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

socket = None

def setsocket(sock):
    global socket
    socket = sock


def getsocket():
    global socket
    return socket

###################################################

# import socket
# from asgiref.wsgi import WsgiToAsgi, WsgiToAsgiInstance

# class decorated_WsgiToAsgiInstance(WsgiToAsgiInstance):
#     def build_environ(self, scope, body):
#         print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$Hello Brother!")
#         filtered_conn = psutil.net_connections() #filter(lambda conn: conn.raddr and conn.raddr.ip == '::1' and conn.raddr.port == 9000, psutil.net_connections())
#         conn_list=list(filtered_conn)
#         count=len(conn_list)
#         lc=conn_list[count-1]
#         print(lc)
#         p=psutil.Process(lc.pid)
#         print(p)
#         return super().build_environ(scope, body)

# class decorated_WsgiToAsgi(WsgiToAsgi):
#     async def __call__(self, scope, receive, send):
#         await decorated_WsgiToAsgiInstance(self.wsgi_application)(scope, receive, send)