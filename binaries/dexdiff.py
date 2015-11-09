#!/usr/bin/env python
# Android Device Testing Framework ("dtf")
# Copyright 2013-2015 Jake Valletta (@jake_valletta)
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
"""Compare DEX DBs"""

import sqlite3
import os
from sys import argv

# Stolen from stackoverflow:D
def countOnes(i):
    assert 0 <= i < 0x100000000
    i = i - ((i >> 1) & 0x55555555)
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333)
    return (((i + (i >> 4) & 0xF0F0F0F) * 0x1010101) & 0xffffffff) >> 24

kAccessForClass = 0
kAccessForMethod = 1
kAccessForField = 2

def createAccessFlagStr(flags, forWhat):

    NUM_FLAGS = 18

    kAccessStrings = [[   # Class, inner class
                  "public",
                  "private",
                  "protected",
                  "static",
                  "final",
                  "?",
                  "?",
                  "?",
                  "?",
                  "interface",
                  "abstract",
                  "?",
                  "synthetic",
                  "annotation",
                  "enum",
                  "?",
                  "verified",
                  "optimized"
                  ],
                  [       # Method
                  "public",
                  "private",
                  "protected",
                  "static",
                  "final",
                  "synchronized",
                  "bridge",
                  "varags",
                  "native",
                  "?",
                  "abstract",
                  "strict",
                  "synthetic",
                  "?",
                  "?",
                  "miranda",
                  "constructor",
                  "declared_synchronized"
                  ],
                  [      # Field
                  "public",
                  "private",
                  "protected",
                  "static",
                  "final",
                  "?",
                  "volatile",
                  "transient",
                  "?",
                  "?",
                  "?",
                  "?",
                  "synthetic",
                  "?",
                  "enum",
                  "?",
                  "?",
                  "?"
                  ]
                 ]

    count = countOnes(flags)

    cp = ""

    for i in range(0, NUM_FLAGS):
        if flags & 0x01:
            accessStr = kAccessStrings[forWhat][i]
            if cp != "":
                cp += ' '+accessStr
            else:
                cp = accessStr

        flags >>= 1
    return cp

db1 = argv[1]
db2 = argv[2]

if not os.path.isfile(db1):
    print "[ERROR] File \'%s\' does not exist." % db1
    exit(-1)

if not os.path.isfile(db2):
    print "[ERROR] File \'%s\' does not exist." % db2
    exit(-1)

conn_local = sqlite3.connect(db1)
conn_aosp = sqlite3.connect(db2)

cur_aosp = conn_aosp.cursor()

# Get a list of all classes from our project
sql = ('SELECT id, name, access_flags, superclass '
       'FROM classes')

for row in conn_local.execute(sql):

    class_id = row[0]#str(row[0])
    class_name = row[1]
    class_access_flags = int(row[2])
    class_superclass = row[3]

    # See if we can find that class in the AOSP
    sql = ('SELECT id '
           'FROM CLASSES '
           'WHERE name="%s"' % class_name)

    cur_aosp.execute(sql)

    if cur_aosp.fetchone() == None:

        if class_access_flags == 0:
            class_access_flag_str = "public"
        else:
            class_access_flag_str = createAccessFlagStr(class_access_flags,
                                                        kAccessForClass)

        print "[New Class] %s %s" % (class_access_flag_str, class_name)

        # Get a listing of all static fields
        sql = ('SELECT name, type, access_flags '
               'FROM static_fields '
               'WHERE class_id=%d' % class_id)

        for row in conn_local.execute(sql):

            sfield_name = row[0]
            sfield_type = row[1]
            sfield_access_flags = int(row[2])

            sfield_access_flags_str = createAccessFlagStr(sfield_access_flags,
                                                          kAccessForField)
            if sfield_access_flags_str == '':
                sfield_line = "%s %s" % (sfield_type, sfield_name)
            else:
                sfield_line = "%s %s %s" % (sfield_access_flags_str,
                                            sfield_type, sfield_name)

            print "   [Static Field] %s" % (sfield_line)

        # Get a listing of all instance fields
        sql = ('SELECT name, type, access_flags '
               'FROM instance_fields '
               'WHERE class_id=%d' % class_id)

        for row in conn_local.execute(sql):

            ifield_name = row[0]
            ifield_type = row[1]
            ifield_access_flags = int(row[2])

            ifield_access_flags_str = createAccessFlagStr(ifield_access_flags,
                                                          kAccessForField)
            if ifield_access_flags_str == '':
                ifield_line = "%s %s" % (ifield_type, ifield_name)
            else:
                ifield_line = "%s %s %s" % (ifield_access_flags_str,
                                            ifield_type, ifield_name)

            print "   [Instance Field] %s" % (ifield_line)

        # Get a listing of all method details
        sql = ('SELECT name, descriptor, access_flags '
               'FROM methods '
               'WHERE class_id=%d' % class_id)

        for row in conn_local.execute(sql):

            method_name = row[0]
            method_descriptor = row[1]
            method_access_flags = int(row[2])

            method_access_flags_str = createAccessFlagStr(method_access_flags,
                                                          kAccessForMethod)
            if method_access_flags_str == '':
                method_line = "%s%s" % (method_name, method_descriptor)
            else:
                method_line = "%s %s%s" % (method_access_flags_str,
                                           method_name, method_descriptor)

            print "   [Method] %s" % (method_line)
    else:
        pass

