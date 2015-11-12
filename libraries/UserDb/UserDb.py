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
"""API for working with Linux Users"""
import sqlite3
import os.path

from dtf.globals import DTF_PACKAGES_DIR
import dtf.properties as prop

_TAG = "UserDb"

USERS_DB_NAME = "users.db"

AOSP_PACKAGE_PREFIX = "aosp-data-"

# Check if we can the api data
def isAOSPDataInstalled():

    """Determine if AOSP data is installed"""

    sdk = prop.get_prop("Info", "sdk")

    if os.path.isdir(DTF_PACKAGES_DIR + '/' + AOSP_PACKAGE_PREFIX + sdk):
        return True
    else:
        return False

# Exceptions
class UserDbException(Exception):

    """Generic exception"""

    def __init__(self, message):

        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)
# End Component Class Declarations

#### Class AppDb ########################################
class UserDb(object):

    """Class for manipulating users"""

    db_path = None
    users_db = None

    def __init__(self, db_path, safe=False):

        """Object initialization"""

        # Make sure the DB exists, don't create it.
        if safe and not os.path.isfile(db_path):
            raise UserDbException("Database file not found : %s!" %
                    db_path)

        self.db_path = db_path
        self.users_db = sqlite3.connect(db_path)

    def close(self):

        """Close handle to DB"""

        self.users_db.close()

#### Table Querying Methods ############################
    def userExists(self, user_name):

        """Determine if a user is installed. Return UID or None"""

        user_exists = self.getUserId(user_name)

        if user_exists is None:
            return False
        else:
            return True

    def getUsers(self):

        """Get all users"""

        user_list = list()

        sql = ('SELECT id, name '
               'FROM users '
               'ORDER BY id')

        cur = self.users_db.cursor()
        cur.execute(sql)

        for user_id, user_name in cur.fetchall():

            user = dict()
            user['id'] = user_id
            user['name'] = user_name

            user_list.append(user)

        return user_list

    def getUserId(self, user_name):

        """Get the user ID for a given name"""

        sql = ('SELECT id '
              'FROM users '
              "WHERE name='%s'" % user_name)

        cur = self.users_db.cursor()
        cur.execute(sql)

        try:
            return cur.fetchone()[0]
        except TypeError:
            return None

    def getUserName(self, user_id):

        """Get user name for a given ID"""

        sql = ('SELECT name '
              'FROM users '
              "WHERE id=%d" % user_id)

        cur = self.users_db.cursor()
        cur.execute(sql)

        try:
            return cur.fetchone()[0]
        except TypeError:
            return None
# End class FrameworkDb
