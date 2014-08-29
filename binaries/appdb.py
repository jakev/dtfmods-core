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
# Application Database (AppDb) Manipulation
from pydtf import dtfconfig, dtfglobals
from pydtf import dtflog as log
from sqlite3 import connect
from base64 import b64encode, b64decode
from sys import argv
from os import listdir
from os.path import isdir, isfile
from argparse import ArgumentParser
import AppDb

try:
    from lxml import etree
except ImportError:
    raise ImportError('This module requires the python module "lxml" to use. Please install it!')
    exit(-5)


APP_DB = dtfconfig.get_prop("Local", "db-dir")+"/sysapps.db"

__VERSION__ = "1.0"

#log.LOG_LEVEL_STDOUT = 5

TAG = "appdb.py"
app_db = None

FILTER_ACTIVITIES = "activities"
FILTER_SERVICES = "services"
FILTER_PROVIDERS = "providers"
FILTER_RECEIVERS = "receivers"

def usage():
    print "AppDb DTF Module Version %s" % __VERSION__
    print ""
    print "Submodules:"
    print "    create      Create the appdb database."
    print "    diff        Diff an AOSP application(s) against local db."
    print "    exposed     Determine exposure of an application(s)."
    print ""
    exit(0)

# SQL Stuff
def encodeTags(tag, xpath):

    data = ""
    for sub_tag in tag.findall(xpath):
        data += etree.tostring(sub_tag)

    return b64encode(data)

def combineTags(tag, xpath):

    data = ""
    for sub_tag in tag.findall(xpath):
        data += etree.tostring(sub_tag)

    return data

def isGoogleApp(package_name):
    if package_name[0:11] == "com.google.":
        return True
    else:
        return False

########################################################################

# Misc
def getAttrib(element, attrib, default="None"):

    try:
        return element.attrib['{http://schemas.android.com/apk/res/android}'+attrib]
    except KeyError:
        return default

def initializeActivityCsv(base_name):

    full_name = base_name + "_activities.csv"

    if isfile(full_name):
        print "[ERROR] File '%s' already exists! Exiting." % full_name
        exit(-3)  

    tmp_f = open(full_name, 'w') 
    tmp_f.write("Application Name,Activity Name,Permission,Intent Data,Export Reason\n")
    return tmp_f


def initializeServiceCsv(base_name):

    full_name = base_name + "_services.csv"

    if isfile(full_name): 
        print "[ERROR] File '%s' already exists! Exiting." % full_name
        exit(-3)
    

    tmp_f = open(full_name, 'w') 
    tmp_f.write("Application Name,Service Name,Permission,Intent Data,Export Reason\n")
    return tmp_f

def initializeProviderCsv(base_name):

    full_name = base_name + "_providers.csv"

    if isfile(full_name): 
        print "[ERROR] File '%s' already exists! Exiting." % full_name
        exit(-3)
    
    tmp_f = open(full_name, 'w') 
    tmp_f.write(('Application Name,Provider Name,Authorities,Read Permission,Write Permission,'
                 'Permission,Export Reason\n'))
    return tmp_f

def initializeReceiverCsv(base_name):

    full_name = base_name + "_receivers.csv"

    if isfile(full_name): 
        print "[ERROR] File '%s' already exists! Exiting." % full_name
        exit(-3)
    
    tmp_f = open(full_name, 'w') 
    tmp_f.write("Application Name,Receiver Name,Permission,Intent Data,Export Reason\n")
    return tmp_f

def csvActivity(file_f, app_name, activity, reason):
    pass
def csvService(file_f, app_name, service, reason):
    pass
def csvProvider(file_f, app_name, provider, reason):

    authorities = "|".join(provider.authorities)

    if provider.permission == None:
        permission = None
    else:
        permission = provider.permission.name

    if provider.read_permission == None:
        read_permission = None
    else:
        read_permission = provider.read_permission.name

    if provider.write_permission == None:
        write_permission = None
    else:
        write_permission = provider.write_permission.name

    print provider.permission, provider.read_permission, provider.write_permission

    file_f.write("%s,%s,%s,%s,%s,%s,,%s\n" % (app_name, provider.name, authorities, read_permission,
                                          write_permission, permission, reason))
                 
def csvReceiver(file_f, app_name, receiver, reason):
    pass





def printActivity(activity):

    print "   %s" % (activity.name)
    print "       Permission: %s" % str(activity.permission)
    print "       Enabled: %s" % str(activity.enabled)
    print "       Exported: %s" % str(activity.exported)

    if len(activity.intent_data) != 0:
        print "       Intent Data:"
        print "       %s" % activity.intent_data

def printService(service):

    print "   %s" % (service.name)
    print "       Permission: %s" % str(service.permission)
    print "       Enabled: %s" % str(service.enabled)
    print "       Exported: %s" % str(service.exported)
    if len(service.intent_data) != 0:
        print "       Intent Data:"
        print "       %s" % service.intent_data

def printProvider(provider):

    print "   %s" % (provider.name)
    print "       Authorities: %s" % ",".join(provider.authorities)
    print "       Permission: %s" % str(provider.permission)
    print "       Read Permission: %s" % str(provider.read_permission)
    print "       Write Permission: %s" % str(provider.write_permission)
    print "       Enabled: %s" % provider.enabled
    print "       Exported: %s" % provider.exported
    print "       Granted URI Permissions: %s" % provider.grant_uri_permissions

    if len(provider.grant_uri_permission_data) > 0:
        print "       Grant URI Permissions:"
        print "       %s" % provider.grant_uri_permission_data

    if len(provider.path_permission_data) > 0:
        print "       Path Permissions:"
        print "       %s" % provider.path_permission_data

def printReceiver(receiver):

    print "   %s" % (receiver.name)
    print "       Permission: %s" % str(receiver.permission)
    print "       Enabled: %s" % str(receiver.enabled)
    print "       Exported: %s" % str(receiver.exported)
    if len(receiver.intent_data) != 0:
        print "       Intent Data:"
        print "       %s" % receiver.intent_data

# Processing
def parsePermissionGroups(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for pg in root.findall(".//permission-group"):

        permission_group = AppDb.PermissionGroup( getAttrib(pg, "name"), application_id)

        log.d(TAG, "Adding <permission-group> : %s" % (permission_group.name))

        if (appdb.addPermissionGroup(permission_group)):
            log.d(TAG, "Permission group added!")
        else:
            log.e(TAG, "Error adding permission-group!")

    appdb.commit()

def parsePermissions(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for p in root.findall(".//permission"):

        name = getAttrib(p, "name")
        permission_group_name = getAttrib(p, "permissionGroup")
        protection_level = getAttrib(p, "protectionLevel")

        log.d(TAG, "Adding <permission> : %s" % (name))

        # First, lets get the group for this permission
        if permission_group_name != "None":
            permission_group = appdb.resolveGroupByName(permission_group_name)
        else:
            permission_group = None


        if protection_level == "None":
            log.w(TAG, "This permission doesnt have a protection...hmmmm...")
            protection_level = "normal"

        if protection_level[0:2] == "0x":
            protection_level = AppDb.protectionToString( int(protection_level, 16))


        permission = AppDb.Permission(name, protection_level, permission_group, application_id)

        if (appdb.addPermission(permission)):
            log.d(TAG, "Permission added!")
        else:
            log.e(TAG, "Error adding permission!")

    appdb.commit()

def parseActivities(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for a in root.findall(".//application/activity"):

        name = getAttrib(a, "name")
        enabled = getAttrib(a, "enabled", default=None)
        exported = getAttrib(a, "exported", default=None)
        permission_name = getAttrib(a, "permission")

        log.d(TAG, "Adding <activity> : %s" % (name))

        intent_filter_data = ""

        for intent_filter in a.findall(".//intent-filter"):
            intent_filter_data += etree.tostring(intent_filter)

        if enabled == None:
            pass
        elif enabled == "true":
            enabled = True
        elif enabled == "false":
            enabled = False
        else:
            log.w(TAG, "Found weird enabled in parseActivities : %s" % enabled)
            enabled = None

        if exported == None:
            pass
        elif exported == "true":
            exported = True
        elif exported == "false":
            exported = False
        else:
            log.w(TAG, "Found weird exported in parseActivities : %s" % exported)
            exported = None

        permission = None

        if permission_name is not "None":
            permission = appdb.resolvePermissionByName(permission_name)

            # This is the error case.
            if permission is None:
                log.w(TAG, "[addActivity] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, permission_name))

        activity = AppDb.Activity(name, enabled, exported, permission, intent_filter_data,
                                  application_id)

        if (appdb.addActivity(activity)):
            log.d(TAG, "Activity added!")
        else:
            log.e(TAG, "Error adding activity!")

    appdb.commit()

def parseServices(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for s in root.findall(".//application/service"):

        name = getAttrib(s, "name")
        enabled = getAttrib(s, "enabled", default=None)
        exported = getAttrib(s, "exported", default=None)
        permission_name = getAttrib(s, "permission")

        log.d(TAG, "Adding <service> : %s" % (name))

        intent_filter_data = ""

        for intent_filter in s.findall(".//intent-filter"):
            intent_filter_data += etree.tostring(intent_filter)

        if enabled == None:
            pass
        elif enabled == "true":
            enabled = True
        elif enabled == "false":
            enabled = False
        else:
            log.w(TAG, "Found weird enabled in parseServices : %s" % enabled)
            enabled = None
                
        if exported == None:
            pass
        elif exported == "true":
            exported = True
        elif exported == "false":
            exported = False
        else:
            log.w(TAG, "Found weird exported in parseServices : %s" % exported)
            exported = None

        permission = None

        if permission_name is not "None":
            permission = appdb.resolvePermissionByName(permission_name)

            # This is the error case.
            if permission is None:
                log.w(TAG, "[addService] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, permission_name))

        service = AppDb.Service(name, enabled, exported, permission, intent_filter_data, 
                                application_id)

        if (appdb.addService(service)):
            log.d(TAG, "Service added!")
        else:
            log.e(TAG, "Error adding service!")

    appdb.commit()

def parseProviders(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for p in root.findall(".//application/provider"):

        name = getAttrib(p, "name")
        authorities = getAttrib(p, "authorities").split(';')
        enabled = getAttrib(p, "enabled", default=None)
        exported = getAttrib(p, "exported", default=None)
        permission_name = getAttrib(p, "permission")
        read_permission_name = getAttrib(p, "readPermission")
        write_permission_name = getAttrib(p, "writePermission")
        grant_uri_permissions = getAttrib(p, "grantUriPermissions", default=None)

        log.d(TAG, "Adding <provider> : %s" % (name))

        if enabled == None:
            pass
        elif enabled == "true":
            enabled = True
        elif enabled == "false":
            enabled = False
        else:
            log.w(TAG, "Found weird enabled in parseProvider : %s" % enabled)
            enabled = None

        if exported == None:
            pass
        elif exported == "true":
            exported = True
        elif exported == "false":
            exported = False
        else:
            log.w(TAG, "Found weird exported in parseProvider : %s" % exported)
            exported = None

        if grant_uri_permissions == None:
            pass
        elif grant_uri_permissions == "true":
            grant_uri_permissions = 1
        elif grant_uri_permissions == "false":
            grant_uri_permissions = 0
        else:
            log.w(TAG, "Found weird grantUriPermissions in parseProvider : %s" % grant_uri_permissions)
            grant_uri_permissions = None

        permission = None
        read_permission = None
        write_permission = None

        if permission_name is not "None":
            permission = appdb.resolvePermissionByName(permission_name)

            # This is the error case.
            if permission is None:
                log.w(TAG, "[addProvider] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, permission_name))

        if read_permission_name is not "None":
            read_permission = appdb.resolvePermissionByName(read_permission_name)

            # This is the error case.
            if read_permission is None:
                log.w(TAG, "[addProvider] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, read_permission_name))

        if write_permission_name is not "None":
            write_permission = appdb.resolvePermissionByName(write_permission_name)

            # This is the error case.
            if write_permission is None:
                log.w(TAG, "[addProvider] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, write_permission_name))

        grant_uri_permission_data = combineTags(p, ".//grant-uri-permission")

        path_permission_data = combineTags(p, ".//path-permission")

        provider = AppDb.Provider(name, authorities, enabled, exported, grant_uri_permissions,
                                  grant_uri_permission_data, path_permission_data,
                                  permission, read_permission, write_permission, application_id)

        if (appdb.addProvider(provider)):
            log.d(TAG, "Provider added!")
        else:
            log.e(TAG, "Error adding provider!")

    appdb.commit()

def parseReceivers(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for r in root.findall(".//application/receiver"):


        name = getAttrib(r, "name")
        enabled = getAttrib(r, "enabled", default=None)
        exported = getAttrib(r, "exported", default=None)
        permission_name = getAttrib(r, "permission")

        intent_filter_data = ""

        for intent_filter in r.findall(".//intent-filter"):
            intent_filter_data += etree.tostring(intent_filter)

        log.d(TAG, "Adding <receiver> : %s" % (name))

        if enabled == None:
            pass
        elif enabled == "true":
            enabled = True
        elif enabled == "false":
            enabled = False
        else:
            log.w(TAG, "Found weird enabled in parseReceivers : %s" % enabled)
            enabled = None

        if exported == None:
            pass
        elif exported == "true":
            exported = True
        elif exported == "false":
            exported = False
        else:
            log.w(TAG, "Found weird exported in parseReceivers : %s" % exported)
            exported = None

        permission = None

        if permission_name is not "None":
            permission = appdb.resolvePermissionByName(permission_name)

            # This is the error case.
            if permission is None:
                log.w(TAG, "[addReceiver] {%s} I was unable to find the permission \"%s\", how can this be?" % (name, permission_name))

        receiver = AppDb.Receiver(name, enabled, exported, permission, intent_filter_data, 
                                  application_id)

        if (appdb.addReceiver(receiver)):
            log.d(TAG, "Receiver added!")
        else:
            log.e(TAG, "Error adding receiver!")

    appdb.commit()

def parseAppUsesPermissions(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    for up in root.findall(".//uses-permission"):

        permission_name = getAttrib(up, "name")
        #permission_id  = appdb.resolvePermissionIdByString(permission_name)
        permission  = appdb.resolvePermissionByName(permission_name)


        log.d(TAG, "Adding <uses-permission> : %s" % (permission_name))

        if permission == None:
            log.w(TAG, "I was unable to resolve the use-permission to an application defining it: \"%s\", continuing!" % permission_name)
            continue

        if (appdb.addAppUsesPermission(application_id, permission._id)):
            log.d(TAG, "Uses-permission added!")
        else:
            log.e(TAG, "Error adding uses-permission!")

    appdb.commit()

def parseUsesSdk(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    application = appdb.getAppById(application_id)

    min_sdk_version = 0
    target_sdk_version = 0

    sdk_tags = root.findall(".//uses-sdk")

    if len(sdk_tags) == 0:
        min_sdk_version = 1
        target_sdk_version = min_sdk_version

    else:
        min_sdk_version = getAttrib(sdk_tags[0], "minSdkVersion", 1)
        target_sdk_version = getAttrib(sdk_tags[0], "targetSdkVersion", min_sdk_version)

    application.min_sdk_version = min_sdk_version
    application.target_sdk_version = target_sdk_version

    appdb.updateApplication(application)  

    appdb.commit()

def parseAppPermission(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    name = root.xpath(".//application/@android:permission",
                   namespaces = {'android' : 'http://schemas.android.com/apk/res/android'})

    permission = None
    if len(name) == 1:

        permission = appdb.resolvePermissionByName(name[0])

        # This is the error case.
        if permission is None:
            log.w(TAG, "[AppPermission] {%s} I was unable to find the permission \"%s\", how can this be?" % (manifest_path, name))
            return

        application = appdb.getAppById(application_id)
        application.permission = permission
        appdb.updateApplication(application)
    
    appdb.commit()

def parseDebuggable(appdb, application_id, manifest_path):

    manifest_f = open(manifest_path)

    try:   
        root = etree.XML(manifest_f.read())
    except etree.XMLSyntaxError:
        log.e(TAG, "The manifest for this application is corrupt! Skipping.")
        return -4

    application = appdb.getAppById(application_id)

    debuggable_name = root.xpath(".//application/@android:debuggable",
                   namespaces = {'android' : 'http://schemas.android.com/apk/res/android'})

    if len(debuggable_name) == 1:

        if debuggable_name == "true":
            application.setDebuggable(True)
        elif debuggable_name == "false":
            application.setDebuggable(False)
    else:
        application.setDebuggable(None)

    appdb.updateApplication(application)
    appdb.commit()


def parseShared(appdb, application_id, libs_dir):

    if isdir(libs_dir):
        log.i(TAG, "Libs dir exists, finding shared libs!")

        arm_files = []
        armv7a_files = []

        # For now, we only look for armeabi, or armeabi-v7a
        try:
            arm_files = listdir(libs_dir+"armeabi")
        except OSError:
            pass

        try:
            armv7a_files = listdir(libs_dir+"armeabi-v7a")
        except OSError:
            pass

        print arm_files, armv7a_files

        application = appdb.getAppById(application_id)
        if len(arm_files) > 0 or len(armv7a_files) > 0:
            application.has_native = 1
        else:
            application.has_native = 0

        appdb.updateApplication(application)


        for lib in arm_files:
            appdb.addShared(application_id, "armeabi/"+lib)

        for lib in armv7a_files:
            appdb.addShared(application_id, "armeabi-v7a/"+lib)
  
        appdb.commit()

    else:
        log.v(TAG, "No libs for this package.")
        return


def cmdCreate():

    # First, we are going to iterate over the apps we have in the system.db
    appdb = AppDb.AppDb('.dbs/'+AppDb.APP_DB_NAME)

    # Drop all the old data
    appdb.dropTables()

    # Create new ones!
    appdb.createTables()

    # First pass just adds <permission-groups>
    log.i(TAG, "Doing first pass...")

    for row in appdb.getApps():

        project_id = row[0]
        project_name = row[2]
        decoded_path = row[3]

        log.i(TAG, "Doing project %s..." % (project_name))

        if decoded_path == None:
            log.e(TAG, "No project path for \"%s\", this package was not decoded successfully. SKIPPING." % project_name)
            continue

        manifest_path = decoded_path+"/AndroidManifest.xml"

        log.i(TAG, "Parsing <permission-group> tags for %s" % project_name)
        parsePermissionGroups(appdb, project_id, manifest_path)

    ############################################################################


    # Second pass does <permissions>
    log.i(TAG, "Doing second pass...")

    for row in appdb.getApps():

        project_id = row[0]
        project_name = row[2]
        decoded_path = row[3]

        log.i(TAG, "Doing project %s..." % (project_name))

        if decoded_path == None:
            log.e(TAG, "No project path for \"%s\", this package was not decoded successfully. SKIPPING." % project_name)
            continue

        manifest_path = decoded_path+"/AndroidManifest.xml"

        log.i(TAG, "Parsing <permission> tags for %s" % project_name)
        parsePermissions(appdb, project_id, manifest_path)

    ############################################################################

    # Final pass does the components, <uses-permission>, shared libs, and <uses-sdk>
    log.i(TAG, "Doing the final pass...")

    for row in appdb.getApps():

        project_id = row[0]
        project_name = row[2]
        decoded_path = row[3]

        log.i(TAG, "Doing project %s..." % (project_name))

        if decoded_path == None:
            log.e(TAG, "No project path for \"%s\", this package was not decoded successfully. SKIPPING." % project_name)
            continue

        manifest_path = decoded_path+"/AndroidManifest.xml"

        log.i(TAG, "Parsing <uses-permission> tags for %s" % project_name)
        parseAppUsesPermissions(appdb, project_id, manifest_path)

        log.i(TAG, "Looking for permission attribute for application %s..." % project_name)
        parseAppPermission(appdb, project_id, manifest_path)

        #log.i(TAG, "Parsing <uses-sdk> tags for %s" % project_name)
        #parseUsesSdk(appdb, project_id, manifest_path)

        log.i(TAG, "Parsing <activity> tags for %s" % project_name)
        parseActivities(appdb, project_id, manifest_path)

        log.i(TAG, "Parsing <service> tags for %s" % project_name)
        parseServices(appdb, project_id, manifest_path)

        log.i(TAG, "Parsing <provider> tags for %s" % project_name)
        parseProviders(appdb, project_id, manifest_path)

        log.i(TAG, "Parsing <reciever> tags for %s" % project_name)
        parseReceivers(appdb, project_id, manifest_path)

        # Now look for the native code.
        log.i(TAG, "Looking for shared libraries.")
        libs_dir = decoded_path+"/lib/"
        parseShared(appdb, project_id, libs_dir)

    # Write it all out
    appdb.commit()

# Print all permissions and where they are defined
def enumeratePermissions():

    global app_db

    app_db = connect(APP_DB)

    sql = ('SELECT p.name, a.project_name, p.protection_level, pg.name '
           'FROM permissions p '
           'JOIN apps a ON a.id = p.application_id '
           'JOIN permission_groups pg ON pg.id = p.permission_group '
           'ORDER BY a.project_name')

    for row in app_db.execute(sql):
        permission_name = row[0]
        application_name = row[1]
        permission_protection = row[2]
        permission_group = row[3]

        print "%s|%s|%s|%s" % (application_name, permission_name, permission_protection, permission_group)

    app_db.close()

def enumerateShared():

    global app_db

    app_db = connect(APP_DB)

    sql = ('SELECT sl.name, a.project_name '
           'FROM shared_libraries sl '
           'JOIN apps a ON a.id=sl.application_id '
           'ORDER BY a.project_name')

    for row in app_db.execute(sql):
        shared_library_name = row[0]
        project_name = row[1]

        print "%s (%s)" % (shared_library_name, project_name)


def showApplication(app_name):

    global app_db

    app_db = connect(APP_DB)

    if app_name == None:
        sql = ('SELECT p.name, p.protection_level, pg.name '
               'FROM app_uses_permissions aup '
               'JOIN apps a ON a.id=aup.application_id '
               'JOIN permissions p ON p.id=aup.permission_id '
               'JOIN permission_groups pg on pg.id=p.permission_group '
               'ORDER BY p.name ')        
    else:

        sql = ('SELECT p.name, p.protection_level, pg.name '
               'FROM app_uses_permissions aup ' 
               'JOIN apps a ON a.id=aup.application_id '
               'JOIN permissions p ON p.id=aup.permission_id '
               'JOIN permission_groups pg on pg.id=p.permission_group '
               'WHERE a.project_name="%s"'
               'ORDER BY p.name ' % app_name)

    print "Uses Permissions:"

    for row in app_db.execute(sql):
        permission_name = row[0]
        permission_protection = row[1]
        permission_group = row[2]

        print "   %s [%s]" % (permission_name, permission_protection)

def doExposed(appdb, app, config):

    filter = config['filter']

    csv_mode = config['csv_mode']
    no_google = config['no_google']

    if app is None:
        print "[ERROR] Unable to find application '%s' in DB. Exiting." % app_name
        return -1

    app_name = app.project_name

    if no_google and isGoogleApp(app_name):
        log.i(TAG, "Skipping Google app '%s'" % app_name)
        return

    log.i(TAG, "app_name : %s" % app_name)

    application_id = app._id
    min_sdk_version = app.min_sdk_version
    target_sdk_version = app.target_sdk_version

    debuggable = app.getDebuggable()

    if debuggable: print "[!!!] This application is debuggable, bad!!"

    ############# Parsing ##############
    if FILTER_ACTIVITIES in filter:

        print "[+] Printing exposed activities..."
        # Let's get exposed activities.
        for activity in appdb.getAppActivities(application_id):
            enabled = activity.enabled
            exported = activity.exported
            intent_data = activity.intent_data

            # First, if we're debuggable, the world is our oyster.
            if debuggable:
                if csv_mode: csvActivity(config['activity_csv_f'], app_name, activity, "Debuggable Flag")
                else: 
                    print "   [EXP] Activity exported due to debuggable flag!"
                    printActivity(activity)
            else:
                # Debuggable isnt set.
                # First, lets make sure there is a permission that we can work with. No sig|sys.
                if activity.permission is not None:

                    protection_level = activity.permission.protection_level
                    if protection_level not in['dangerous', 'normal', 'development']:
                        continue

                # Is this even enabled?
                if enabled is False: continue

                # Is it explicitly set to false?
                if exported is False: continue

                # How about an explicit export?
                elif exported is True:
                    if csv_mode: csvActivity(config['activity_csv_f'], app_name, 
                                             activity, "Explicit Export")
                    else:
                        print "   [EXP] Explicit export flag!"
                        printActivity(activity)

                # Ok, this is the weird case.
                elif exported is None and len(intent_data) != 0:
                    if csv_mode: csvActivity(config['activity_csv_f'], app_name, 
                                             activity, "Implicit Export")
                    else:
                        print "   [EXP] Implicit export by intent-filter!"
                        printActivity(activity)

    if FILTER_SERVICES in filter:

        print "[+] Printing exposed services..."
        # Let's get exposed services.
        for service in appdb.getAppServices(application_id):
            enabled = service.enabled
            exported = service.exported
            intent_data = service.intent_data

            # First, if we're debuggable, the world is our oyster.
            if debuggable:
                print "   [EXP] Service exported due to debuggable flag!"
                print printService(service)
            else:
                # Debuggable isnt set.
                # First, lets make sure there is a permission that we can work with. No sig|sys.
                if service.permission is not None:

                    protection_level = service.permission.protection_level
                    if protection_level not in['dangerous', 'normal', 'development']:
                        continue

                # Is this even enabled?
                if enabled is False: continue

                # Is it explicitly set to false?
                if exported is False: continue

                # How about an explicit export?
                elif exported is True:
                    print "   [EXP] Explicit export flag!"
                    printService(service)

                # Ok, this is the weird case.
                elif exported is None and len(intent_data) != 0:
                    print "   [EXP] Implicit export by intent-filter!"
                    printService(service)

    if FILTER_PROVIDERS in filter:

        print "[+] Printing exposed providers..."
        for provider in appdb.getAppProviders(application_id):

            enabled = provider.enabled
            exported = provider.exported

            # First, if we're debuggable, the world is our oyster.
            if debuggable:
                if csv_mode: csvProvider(config['provider_csv_f'], app_name, provider, "Debuggable Flag")
                else:
                    print "   [EXP] Provider exported due to debuggable flag!"
                    printProvider(provider)
            else:
                # Debuggable isnt set.

                # First, lets make sure there are permissions that we can work with.
                read_protection_level = None
                write_protection_level = None
                # This is frustratingly annoying for providers.
                # We're actually going to ignore "permission", is distribute it's effects.

                # First lets set the actual read_permission for this component.
                if provider.permission is None and provider.read_permission is None:
                    read_permission = None
                elif provider.permission is None and provider.read_permission is not None:
                    read_permission = provider.read_permission
                elif provider.permission is not None and provider.read_permission is None:
                    read_permission = provider.permission
                elif provider.permission is not None and provider.read_permission is not None:
                    read_permission = provider.read_permission

                # Same thing for write_permission.
                if provider.permission is None and provider.write_permission is None:
                    write_permission = None
                elif provider.permission is None and provider.write_permission is not None:
                    write_permission = provider.write_permission
                elif provider.permission is not None and provider.write_permission is None:
                    write_permission = provider.permission
                elif provider.permission is not None and provider.write_permission is not None:
                    write_permission = provider.write_permission

                # Lets get the protection levels
                if read_permission is not None:
                    read_protection_level = read_permission.protection_level
                if write_permission is not None:
                    write_protection_level = write_permission.protection_level

                # If both are NOT in the group below, continue. We cant do anything.
                if (read_protection_level not in [None, 'dangerous', 'normal', 'development']
                    and write_protection_level not in [None, 'dangerous', 'normal', 'development']):
                   continue

                # Is this even enabled?
                if enabled is False: continue

                # Is it explicitly set to false?
                if exported is False: continue

                # How about an explicit export?
                elif exported is True:
                    if csv_mode: csvProvider(config['provider_csv_f'], app_name,
                                             provider, "Explicit Export")
                    else:
                        print "   [EXP] Explicit export flag!"
                        printProvider(provider)

                # Ok, this is the weird case.
                elif exported is None:
                    # check the min and targets.
                    if target_sdk_version <= 16:

                        # But we need to check the permissions.
                        # TODO

                        if csv_mode: csvProvider(config['provider_csv_f'], app_name,
                                                 provider, "Bad SDK Version")
                        else:
                            print "   [EXP] Implicit export based on *_sdk_version!"
                            printProvider(provider)


    if FILTER_RECEIVERS in filter:

        print "[+] Printing exposed receivers..."
        # Let's get exposed receivers.
        for receiver in appdb.getAppReceivers(application_id):
            enabled = receiver.enabled
            exported = receiver.exported
            intent_data = receiver.intent_data

            # First, if we're debuggable, the world is our oyster.
            if debuggable:
                print "   [EXP] Receiver exported due to debuggable flag!"
                print printReceiver(receiver)
            else:
                # Debuggable isnt set.
                # First, lets make sure there is a permission that we can work with. No sig|sys.
                if receiver.permission is not None:

                    protection_level = receiver.permission.protection_level
                    if protection_level not in['dangerous', 'normal', 'development']:
                        continue

                # Is this even enabled?
                if enabled is False: continue

                # Is it explicitly set to false?
                if exported is False: continue

                # How about an explicit export?
                elif exported is True:
                    print "   [EXP] Explicit export flag!"
                    printReceiver(receiver)

                # Ok, this is the weird case.
                elif exported is None and len(intent_data) != 0:
                    print "   [EXP] Implicit export by intent-filter!"
                    printReceiver(receiver)

def cmdExposed(args):

    DEFAULT_FILTERS = ['activities','services','providers','receivers']

    config = dict()

    parser = ArgumentParser(prog='appdb exposed',
                            description='Get exposed components of an application.')
    parser.add_argument('app_name', metavar="app_name", type=str, nargs='?', default=None,
                        help='The application to check.')
    parser.add_argument('--filter', dest='filter', default=None, 
                        help='Filter by component type(comma seperated).')
    parser.add_argument('--all', dest='all', action='store_const', const=True, default=False,
                        help='Run against all non-AOSP applications.')
    parser.add_argument('--csv', dest='csv_name', default=None, 
                        help='Output data to CSV.')
    parser.add_argument('--no-google', dest='no_google', action='store_const', const=True,
                        default=False, help='Omit Google packages based on package name.')

    args = parser.parse_args()

    app_name = args.app_name
    all_mode = args.all

    filter = args.filter

    csv_name_base = args.csv_name

    if not all_mode and app_name is None:
        print "You need to specify an application name (or --all)! Try -h for more information. Exiting."
        exit(-1)

    if filter is None: 
        filter = DEFAULT_FILTERS
    else: 
        filter = filter.split(',')

    config['filter'] = filter

    if csv_name_base != None:
        config['csv_mode'] = True

        if FILTER_ACTIVITIES in filter:
            config['activity_csv_f'] = initializeActivityCsv(csv_name_base)

        if FILTER_SERVICES in filter:
            config['service_csv_f'] = initializeServiceCsv(csv_name_base) 

        if FILTER_PROVIDERS in filter:
            config['provider_csv_f'] = initializeProviderCsv(csv_name_base) 

        if FILTER_RECEIVERS in filter:
            config['receiver_csv_f'] = initializeReceiverCsv(csv_name_base)
    else:
        config['csv_mode'] = False

    config['no_google'] = args.no_google

    # Get a handle to our db
    appdb = AppDb.AppDb(APP_DB, safe=True)

    if all_mode:
        for app in appdb.getApps(aosp=False):
            doExposed(appdb, app, config)

    else:
        app = appdb.getAppByName(app_name)
        
        if app is None:
            print "[ERROR] Unable to find application '%s' in DB. Exiting." % app_name
            return -1
        doExposed(appdb, app, config)

def cmdDiff(args):

    print "ok!"

def main(argv):

    # We can pop the program name off
    argv.pop(0)

    # Get the mode
    mode = argv[0]


    if mode == "create":
	cmdCreate()
    elif mode == "exposed":
	cmdExposed(argv)
    elif mode == "diff":
	cmdDiff(argv)
    else:
	usage()

    return 0

if __name__ == '__main__':

    rtn = 0


    if len(argv) < 2:
        usage()
    else:
        rtn = main(argv)

    exit(rtn)

