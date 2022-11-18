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
import testbench_waitress
import testbench
import logging

logger = logging.getLogger("waitress")
logger.setLevel(logging.INFO)

if len(sys.argv) == 4:
    sock_host = sys.argv[1]
    sock_port = int(sys.argv[2])
    num_of_threads = int(sys.argv[3])
    sys.argv.clear()

    testbench_waitress.serve(
        testbench.run(),
        host=sock_host,
        port=sock_port,
        threads=num_of_threads,
        backlog=4096,
        connection_limit=1000,
    )

else:
    print(
        "Invalid number of arguments. Please provide \n <hostname> \n <port> \n <number of threads greater than 10, pass 0 for default value 10>."
    )
