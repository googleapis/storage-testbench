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

"""
Backwards compatibility entry point for the testbench.

The first few pre-releases used this file for the `run()` and `__main__`
entry points. Please switch to:

python -m testbench 

or 

gunicorn testbench:run
"""

import warnings
from testbench import rest_server


def run():
    warnings.warn("Please use testbench:run instead", DeprecationWarning)
    rest_server.logging.basicConfig()
    return rest_server.server


if __name__ == "__main__":
    warnings.warn("Please use `python -m testbench` instead", DeprecationWarning)
    rest_server._main()
