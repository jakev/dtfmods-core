#!/usr/bin/env python
# Copyright 2013-2016 Jake Valletta (@jake_valletta)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Helper methods for various functionality"""

import hashlib
import os
import shlex

from subprocess import Popen, PIPE

# MD5 Related
# Global Helpers
def md5_file(file_path):

    """MD5 a file"""

    try:
        file_f = open(file_path, 'rb')

        my_md5 = hashlib.md5()
        while True:
            data = file_f.read(128)
            if not data:
                break
            my_md5.update(data)
        return my_md5.hexdigest()

    except IOError:
        return None

# XZ Related
def test_xz():

    """Confirm that xz is installed"""

    lexed = shlex.split("command -v xz")

    proc = Popen(lexed, stdout=PIPE, stderr=PIPE, shell=True)
    proc.wait()

    if proc.returncode == 0:
        return True
    else:
        return False

def decompress_xz(file_name):

    """Decompress an xz resource"""

    lexed = shlex.split("xz -d \"%s\"" % file_name)

    proc = Popen(lexed, stdout=PIPE, stderr=PIPE, shell=False)
    proc.wait()

    return proc.returncode
# End XZ Related

# ZIP Related
def extract_from_zip_to(zip_file, extract_path, file_name=None):

    """Extract a file from a ZIP"""

    null_f = open(os.devnull, 'w')

    if file_name is None:
        lexed = shlex.split("unzip -u \"%s\" -d \"%s\""
                                                % (zip_file, extract_path))
    else:
        lexed = shlex.split("unzip -u \"%s\" \"%s\" -d \"%s\""
                                    % (zip_file, file_name, extract_path))

    proc = Popen(lexed, stdout=null_f, stderr=null_f, shell=False)
    proc.wait()

    null_f.close()

    return proc.returncode

def file_in_zip(zip_file, file_name):

    """Determine if file in ZIP"""

    lexed = shlex.split("unzip -t \"%s\" \"%s\"" % (zip_file, file_name))

    proc = Popen(lexed, stdout=PIPE, stderr=PIPE, shell=False)
    proc.wait()

    if proc.returncode == 0:
        return True
    else:
        return False
# End ZIP Related
