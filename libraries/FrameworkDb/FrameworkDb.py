#!/usr/bin/env python
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
# API for working with frameworks
import sqlite3
from os.path import isfile, isdir
from pydtf import dtfglobals
from pydtf import dtfconfig

_TAG = "FrameworkDb"

APP_DB_NAME = "frameworks.db"

AOSP_PACKAGE_PREFIX = "aosp-data-"

# Check if we can the api data
def isAOSPDataInstalled():

    sdk = dtfconfig.get_prop("Info", "sdk")
    dtf_packages = dtfglobals.DTF_PACKAGES

    if isdir(dtf_packages + '/' + AOSP_PACKAGE_PREFIX + sdk):
        return True
    else:
        return False

# Exceptions
class FrameworkDbException(Exception):

    def __init__(self, message):

        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)
# End Component Class Declarations

#### Class AppDb ########################################
class FrameworkDb(object):

    db_path = None
    framework_db = None

    def __init__(self, db_path, safe=False):

        # Make sure the DB exists, don't create it.
        if safe and not isfile(db_path):
            raise FrameworkDbException("Database file not found : %s!" %
                    db_path)

        self.db_path = db_path
        self.framework_db = sqlite3.connect(db_path)

    def close(self):
        self.framework_db.close()

#### Table Creation Methods ############################
    def createTables(self):

        sql = ('CREATE TABLE IF NOT EXISTS frameworks'
               '('
               'id INTEGER PRIMARY KEY AUTOINCREMENT,'
               'name TEXT UNIQUE NOT NULL,'
               'bootclasspath INTEGER,'
               'successfully_unpacked INTEGER DEFAULT 0)')

        self.framework_db.execute(sql)

        return 0
# End Table Creation

#### Table Deletion Methods ############################
    def dropTables(self):

        self.framework_db.execute('''DROP TABLE IF EXISTS frameworks''')

        return 0
# End Table Deletion

#### Table Modification Methods ############################
    def addFrameworks(self, framework_list):

        with self.framework_db:
            cur = self.framework_db.cursor()

            sql = ('INSERT INTO frameworks(name,bootclasspath) '
                  'VALUES(?,?)')

            cur.executemany(sql, framework_list)

        self.framework_db.commit()
        return 1

    def markUnpacked(self, name):

        with self.framework_db:
            cur = self.framework_db.cursor()

            sql = ("UPDATE frameworks SET successfully_unpacked=? "
                   "WHERE name=?")
            cur.execute(sql, (1, name))

        self.framework_db.commit()
        return 1
# End Table Modification

#### Table Querying Methods ############################
    def getFrameworks(self, non_bcp_only=False, 
                      bcp_only=False):

        tmp_frameworks = list()

        if bcp_only:
            sql = ('SELECT name '
                  'FROM frameworks '
                  'WHERE bootclasspath=1 '
                  'ORDER BY name')

        elif non_bcp_only:
            sql = ('SELECT name '
                  'FROM frameworks '
                  'WHERE bootclasspath=0 '
                  'ORDER BY name')

        else:
            sql = ('SELECT name '
                  'FROM frameworks '
                  'ORDER BY name')

        cur = self.framework_db.cursor()
        cur.execute(sql)

        map(lambda x: tmp_frameworks.append(x[0]), cur.fetchall())

        return tmp_frameworks

    def isUnpacked(self, name):

        unpacked = 0

        sql = ('SELECT successfully_unpacked '
               'FROM frameworks '
               "WHERE name='%s'" % name)

        cur = self.framework_db.cursor()
        cur.execute(sql)

        try:
            unpacked = cur.fetchone()[0]
        except TypeError:
            raise FrameworkDbException("Framework not found!")
        
        return unpacked

# End class FrameworkDb
