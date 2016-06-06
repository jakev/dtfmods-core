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
"""API for working with SEAndroid"""

from lxml import etree

import os.path
import re
import sqlite3

from dtf.globals import DTF_PACKAGES_DIR

import dtf.properties as prop
import dtf.logging as log

LIB_TAG = "SeDb"

SE_DB_NAME = "se.db"

AOSP_PACKAGE_PREFIX = "aosp-data-"

FILE_TYPE_ORDINARY = 0
FILE_TYPE_BLOCK = 1
FILE_TYPE_CHAR = 2
FILE_TYPE_DIR = 3
FILE_TYPE_FIFO = 4
FILE_TYPE_SYM = 5
FILE_TYPE_SOCKET = 6

def seapp_attrib(line, attrib, default):

    """Return seapp attrib"""

    compiled = re.compile("(%s=)([\._\-a-zA-Z0-9]*)" % attrib)

    matched = re.search(compiled, line)
    if matched is None:
        return default
    else:
        return matched.group(2)

def determine_type(type_str):

    """Determine the file type"""

    rtn = None

    if type_str == "--":
        rtn = FILE_TYPE_ORDINARY
    elif type_str == "-b":
        rtn = FILE_TYPE_BLOCK
    elif type_str == "-c":
        rtn = FILE_TYPE_CHAR
    elif type_str == "-d":
        rtn = FILE_TYPE_DIR
    elif type_str == "-p":
        rtn = FILE_TYPE_FIFO
    elif type_str == "-l":
        rtn = FILE_TYPE_SYM
    elif type_str == "-s":
        rtn = FILE_TYPE_SOCKET

    return rtn

# Check if we can the api data
def isAOSPDataInstalled():

    """Determine if AOSP data is installed"""

    sdk = prop.get_prop("Info", "sdk")

    if os.path.isdir(DTF_PACKAGES_DIR + '/' + AOSP_PACKAGE_PREFIX + sdk):
        return True
    else:
        return False

# Exceptions
class SeDbException(Exception):

    """Generic exception"""

    def __init__(self, message):

        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)

#### Class SeDb ########################################
class SeDb(object):

    """Class for manipulating SEAndroid information"""

    def __init__(self, db_path, safe=False):

        """Object initialization"""

        # Make sure the DB exists, don't create it.
        if safe and not os.path.isfile(db_path):
            raise SeDbException("Database file not found : %s!" %
                    db_path)

        self.db_path = db_path
        self.se_db = sqlite3.connect(db_path)

    def close(self):

        """Close handle to DB"""

        self.se_db.close()

    def create_tables(self):

        """Create tables"""

        log.d(LIB_TAG, "Creating tables...")

        cur = self.se_db.cursor()

        # File contexts table
        sql = ('CREATE TABLE IF NOT EXISTS file_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'pattern TEXT UNIQUE NOT NULL, '
               'type INTEGER DEFAULT 0, '
               'context TEXT NOT NULL)')

        cur.execute(sql)

        # Seapp contexts table
        sql = ('CREATE TABLE IF NOT EXISTS seapp_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'user TEXT NOT NULL, '
               'seinfo TEXT, '
               'domain TEXT, '
               'name TEXT, '
               'type TEXT)')

        cur.execute(sql)

        # property contexts table
        sql = ('CREATE TABLE IF NOT EXISTS property_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'pattern TEXT UNIQUE NOT NULL, '
               'context TEXT NOT NULL)')

        cur.execute(sql)

        # service contexts table
        sql = ('CREATE TABLE IF NOT EXISTS service_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'name TEXT UNIQUE NOT NULL, '
               'context TEXT NOT NULL)')

        cur.execute(sql)

        # Mac permissions
        sql = ('CREATE TABLE IF NOT EXISTS mac_permissions('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'signature TEXT, context TEXT NOT NULL)')

        cur.execute(sql)

        self.se_db.commit()
        return 0

    def drop_tables(self):

        """Drop tables"""

        cur = self.se_db.cursor()
        cur.execute('DROP TABLE IF EXISTS file_contexts')
        cur.execute('DROP TABLE IF EXISTS seapp_contexts')
        cur.execute('DROP TABLE IF EXISTS property_contexts')
        cur.execute('DROP TABLE IF EXISTS service_contexts')
        cur.execute('DROP TABLE IF EXISTS mac_permissions')

        return 0

    # Testers
    def has_service_contexts(self):

        """Determine if service_contexts exist for this device"""

        sql = ('SELECT COUNT(*) '
               'FROM service_contexts')

        cur = self.se_db.cursor()
        cur.execute(sql)

        (number_of_rows,) = cur.fetchone()

        if number_of_rows == 0:
            return False
        else:
            return True
    # End Testers

    # Parsers
    def parse_file_contexts(self, file_contexts):

        """Parse the file_contexts file"""

        file_contexts_f = open(file_contexts)

        contexts = list()

        for line in file_contexts_f.read().split("\n"):

            if line == "":
                continue
            if line[0] == "#":
                continue

            elements = line.split()

            # 3 elements means there is a type
            if len(elements) == 3:
                pattern, type_str, context = elements
                type_int = determine_type(type_str)
                if type_int is None:
                    log.e(LIB_TAG, "Unsupported type found: %s" % type_str)
                    continue

                contexts.append((pattern, type_int, context))

            elif len(elements) == 2:
                pattern, context = elements
                type_int = FILE_TYPE_ORDINARY

                contexts.append((pattern, type_int, context))

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

        cursor = self.se_db.cursor()
        cursor.executemany('INSERT INTO file_contexts(pattern, type, context) '
                           'VALUES(?, ?, ?)', contexts)
        self.se_db.commit()
        return 0

    def parse_property_contexts(self, property_contexts):

        """Parse the property_contexts file"""

        property_contexts_f = open(property_contexts)

        contexts = list()

        for line in property_contexts_f.read().split("\n"):

            if line == "":
                continue
            if line[0] == "#":
                continue

            elements = line.split()

            if len(elements) == 2:
                pattern, context = elements

                contexts.append((pattern, context))

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

        cursor = self.se_db.cursor()
        cursor.executemany('INSERT INTO property_contexts(pattern, context) '
                           'VALUES(?, ?)', contexts)
        self.se_db.commit()
        return 0

    def parse_seapp_contexts(self, seapp_contexts):

        """Parse the seapp_contexts file"""

        seapp_contexts_f = open(seapp_contexts)

        contexts = list()

        for line in seapp_contexts_f.read().split("\n"):

            if line == "":
                continue

            user = seapp_attrib(line, "user", None)
            if user is None:
                log.d(LIB_TAG, "Skipping non-user entry")
                continue

            seinfo = seapp_attrib(line, "seinfo", None)
            name = seapp_attrib(line, "name", None)
            domain_t = seapp_attrib(line, "domain", None)
            type_t = seapp_attrib(line, "type", None)

            contexts.append((user, seinfo, name, domain_t, type_t))

        cursor = self.se_db.cursor()
        cursor.executemany('INSERT INTO seapp_contexts('
                           'user, seinfo, name, domain, type) '
                           'VALUES(?, ?, ?, ?, ?)', contexts)
        self.se_db.commit()
        return 0

    def parse_service_contexts(self, service_contexts):

        """Parse service contexts"""

        service_contexts_f = open(service_contexts)

        contexts = list()

        for line in service_contexts_f.read().split("\n"):

            if line == "":
                continue
            if line[0] == "#":
                continue

            elements = line.split()

            if len(elements) == 2:
                service_name, context_raw = elements

                if service_name == "*":
                    service_name = "DEFAULT"

                context_name = (context_raw.replace('u:object_r:', '')
                                           .replace(':s0', ''))

                contexts.append((service_name, context_name))

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

        cursor = self.se_db.cursor()
        cursor.executemany('INSERT INTO service_contexts(name, context) '
                           'VALUES(?, ?)', contexts)
        self.se_db.commit()
        return 0

    def parse_mac_permissions(self, mac_permissions_file):

        """parse the MAC permissions file"""

        mac_permissions_list = list()
        mac_permissions_f = open(mac_permissions_file)

        try:
            root = etree.XML(mac_permissions_f.read())
        except etree.XMLSyntaxError:
            log.e(LIB_TAG, "Unable to parse mac_permissions.xml!!")
            return -1

        # Signatures
        for signer in root.findall(".//signer"):

            signer_signature = signer.attrib['signature']
            seinfo_value = ""

            for child in signer:

                #TODO: support package stanzas
                if child.tag == "package":
                    log.w(LIB_TAG, "HEY! Figure this out!")
                elif child.tag == "seinfo":
                    seinfo_value = child.attrib['value']
                    mac_permissions_list.append((signer_signature,
                                                 seinfo_value))
                else:
                    log.e(LIB_TAG, "What is this? '%s'" % child.tag)

        # Default
        for default in root.findall(".//default"):

            # No signature associated with default.
            signer_signature = None

            # Default should only have one child, seinfo.
            seinfo = default[0]
            seinfo_value = seinfo.attrib['value']

            mac_permissions_list.append((signer_signature, seinfo_value))

        cursor = self.se_db.cursor()
        cursor.executemany('INSERT INTO mac_permissions(signature, context) '
                           'VALUES(?, ?)', mac_permissions_list)
        self.se_db.commit()
        return 0

# End Parsers

# Queries
    def get_mac_permissions(self):

        """Return mac permissions"""

        mac_perm_dict = dict()

        sql = ('SELECT context, signature '
               'FROM mac_permissions')

        cur = self.se_db.cursor()
        cur.execute(sql)

        for context, signature in cur.fetchall():

            mac_perm_dict[context] = signature

        return mac_perm_dict

    def get_seapp_rules(self):

        """Return list of seapp rules"""

        seapp_list = list()

        sql = ('SELECT user, seinfo, name, domain, type '
               'FROM seapp_contexts')

        cur = self.se_db.cursor()
        cur.execute(sql)

        for user, seinfo, name, domain_t, type_t in cur.fetchall():

            seapp_list.append((user, seinfo, name, domain_t, type_t))

        return seapp_list

    def get_service_contexts(self):

        """Return a list of service contexts"""

        service_dict = dict()

        sql = ('SELECT name, context '
               'FROM service_contexts')

        cur = self.se_db.cursor()
        cur.execute(sql)

        for name, context in cur.fetchall():

            service_dict[name] = context

        return service_dict

# End class SeDb
