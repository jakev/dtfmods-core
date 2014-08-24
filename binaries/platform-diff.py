#!/usr/bin/env python
# DTF Core Content
# Copyright 2013-2014 Jake Valletta (@jake_valletta)
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
# "platform.xml" diffing support
import sqlite3
from lxml import etree
from pydtf import dtfconfig, dtfglobals
from pydtf import dtflog as log
from os.path import isfile

def safeOpenXML(file_name):

    try:
        f_handle = open(file_name)
    except IOError:
        return -1
       
    root = etree.XML(f_handle.read())

    f_handle.close()

    return root

def safeSqlite3Connect(db):

    if isfile(db):
        return sqlite3.connect(db)

    else:
        raise IOError("Target Sqlite3 file not found!")

def getProtectionLevel(db, permission_name):

    c = db.cursor()

    sql = ('SELECT p.protection_level '
           'FROM permissions p '
           'WHERE p.name="%s" '
           'LIMIT 1' % (permission_name))


    rtn = c.execute(sql)

    try:
        return c.fetchone()[0]
    except TypeError:
        #log.e(TAG, "Unable to find permission?? \"%s\"!" % permission_name)
        return "????"

def parseXML(db, root):



    group_mappings = {}
    account_perms = {}

    # First lets do the mapping
    for element in root.findall(".//permission"):

        permission_name = element.attrib['name']

        gid_name = element.xpath("group")[0].attrib['gid']

        group_mappings[permission_name] = gid_name

    # Now the permission assigns
    for element in root.findall(".//assign-permission"):

        permission_name = element.attrib['name']

        uid = element.attrib['uid']

        if uid in account_perms.keys():
            account_perms[uid].append(permission_name)
        else:
            account_perms[uid] = [ permission_name ]


    return group_mappings, account_perms

TAG = "platformdiff"


try:
    project_db = safeSqlite3Connect('.dbs/sysapps.db')
except IOError:
    print "[Error] The local \"sysapps.db\" does not exist, did you run app2db yet?"
    exit(-1)

aosp_platform_file = dtfglobals.DTF_PACKAGES + "/aosp-data-" + dtfconfig.get_prop("Info", "sdk") + "/platform.xml"

aosp_platform_root = safeOpenXML(aosp_platform_file)

if aosp_platform_root == -1:
    print "Unable to open AOSP platform details. Are you sure you have this API level installed? Exiting!"
    exit(-1)

project_platform_root = safeOpenXML(dtfconfig.get_prop("Local", "permissions-dir")+"/platform.xml")

if project_platform_root == -1:
    print "Unable to open local platform.xml file.  Did you pull it down? Exiting!"
    exit(-1)

project_group_mappings, project_account_perms = parseXML(project_db, project_platform_root)
aosp_group_mappings, aosp_account_perms = parseXML(project_db, aosp_platform_root)

print "[+] OEM Added mappings:"
for name, gid in project_group_mappings.iteritems():

    if name not in aosp_group_mappings:

        protection_level = getProtectionLevel(project_db, name)

        print "\t%s [%s] ---> %s" % (name,protection_level, gid)

print ""
print "[+] OEM Added <assign-permission> tags:"
for uid, permissions in project_account_perms.iteritems():

    if uid not in aosp_account_perms:
        print "\tUser %s [OEM]:" % uid 
        for name in project_account_perms[uid]:
            protection_level = getProtectionLevel(project_db, name)
            print "\t\t+%s [%s]" % (name, protection_level)
    else:
       print "\tUser %s:" % uid
       for name in project_account_perms[uid]:
           if name not in aosp_account_perms[uid]:
               protection_level = getProtectionLevel(project_db, name)
               print "\t\t+%s [%s]" % (name, protection_level)
