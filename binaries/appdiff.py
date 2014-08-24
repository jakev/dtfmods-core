#!/usr/bin/env python
# coding=utf-8
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
# Application Diffing
from pydtf import dtfconfig, dtfglobals
from pydtf import dtflog as log
import sqlite3
from lxml import etree
from base64 import b64encode, b64decode
from sys import argv
import AppDb

log.LOG_LEVEL_FILE=0
log.LOG_LEVEL_STDOUT=3

TAG = "appdiff"


def getAppId(db, name):

    c = db.cursor()

    rtn = c.execute("SELECT id FROM apps WHERE project_name=\"%s\"" % name)

    try:
        return c.fetchone()[0]
    except TypeError:
        log.e(TAG, "Unable to find app \"%s\"!" % name)
        return 0

def permissionInAOSP(db, app_id, permission_name):

    c = db.cursor()

    rtn = c.execute("SELECT id FROM permissions WHERE application_id=%d and name=\"%s\" limit 1" % (app_id, permission_name))

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def appUsesPermissionInAOSP(db, app_id, permission_name):

    # For now, iterate until i code better.
    c = db.cursor()

    rtn = c.execute("SELECT permissions.id FROM app_uses_permissions JOIN permissions ON app_uses_permissions.permission_id=permissions.id WHERE app_uses_permissions.application_id=%d and permissions.name=\"%s\" LIMIT 1" % (app_id, permission_name))

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def appHasActivityInAOSP(db, app_id, name):

    c = db.cursor()

    rtn = c.execute("SELECT activities.id FROM activities JOIN apps ON activities.application_id=apps.id WHERE activities.application_id=%d and activities.name=\"%s\" limit 1" % (app_id, name))

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def appHasServiceInAOSP(db, app_id, name):

    c = db.cursor()

    sql = ('SELECT s.id '
           'FROM services s '
           'JOIN apps a ON a.id=s.application_id '
           'WHERE s.application_id=%d '
           'AND s.name="%s" '
           'LIMIT 1' % (app_id, name))

    rtn = c.execute(sql)

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def appHasProviderInAOSP(db, app_id, name):

    c = db.cursor()

    sql = ('SELECT p.id '
           'FROM providers p '
           'JOIN apps a ON a.id=p.application_id '
           'WHERE p.application_id=%d '
           'AND p.authorities="%s" '
           'LIMIT 1' % (app_id, name))

    rtn = c.execute(sql)

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def appHasReceiverInAOSP(db, app_id, name):

    c = db.cursor()

    sql = ('SELECT r.id '
           'FROM receivers r '
           'JOIN apps a ON a.id=r.application_id '
           'WHERE r.application_id=%d '
           'AND r.name="%s" '
           'LIMIT 1' % (app_id, name))

    rtn = c.execute(sql)

    try:
        c.fetchone()[0]
        return 1
    except TypeError:
        return 0

def getPermissionName(db, permission_id):

    c = db.cursor()

    rtn = c.execute("SELECT name FROM permissions WHERE id=%d limit 1" % permission_id)

    try:
        return c.fetchone()[0]
    except TypeError:
        return None

def getPermissionProtectionLevel(db, permission_id):

    c = db.cursor()

    rtn = c.execute("SELECT protection_level FROM permissions WHERE id=%d limit 1" % permission_id)

    try:
        return c.fetchone()[0]
    except TypeError:
        return None

def safeSqlite3Connect(db):

    if os.path.isfile(db):
        return sqlite3.connect(db)

    else:
        raise IOError("Target Sqlite3 file not found!")

def diffPermissions(local_db, local_application, aosp_db, aosp_application):

    perm_list = list()
    aosp_permissions = aosp_db.getAppPermissions(aosp_application._id)

    for local_permission in local_db.getAppPermissions(local_application._id):

        exists=False
        local_name = local_permission.name
        local_protection_level = local_permission.protection_level

        for aosp_permission in aosp_permissions:
            aosp_name = aosp_permission.name
            aosp_protection_level = aosp_permission.protection_level        

            if aosp_name == local_name and aosp_protection_level == local_protection_level:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            perm_list.append(local_permission)

    if len(perm_list) != 0:
        printPermissions(perm_list)

def diffUsesPermissions(local_db, local_application, aosp_db, aosp_application):

    uses_perm_list = list()
    aosp_uses_permissions = aosp_db.getAppUsesPermissions(local_application._id)

    for local_uses_permission in local_db.getAppUsesPermissions(local_application._id):

        exists=False
        local_name = local_uses_permission.name
        local_protection_level = local_uses_permission.protection_level

        for aosp_uses_permission in aosp_uses_permissions:
            aosp_name = aosp_uses_permission.name
            aosp_protection_level = aosp_uses_permission.protection_level

            if aosp_name == local_name and aosp_protection_level == local_protection_level:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            uses_perm_list.append(local_uses_permission)

    if len(uses_perm_list) != 0:
        printUsesPermissions(uses_perm_list)

def diffActivities(local_db, local_application, aosp_db, aosp_application):

    activity_list = list()
    aosp_activities = aosp_db.getAppActivities(aosp_application._id)

    for local_activity in local_db.getAppActivities(local_application._id):

        exists=False
        local_name = local_activity.name

        for aosp_activity in aosp_activities:
            aosp_name = aosp_activity.name

            if aosp_name == local_name:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            activity_list.append(local_activity)

    if len(activity_list) != 0:
        printActivities(activity_list)

def diffServices(local_db, local_application, aosp_db, aosp_application):

    service_list = list()
    aosp_services = aosp_db.getAppServices(aosp_application._id)

    for local_service in local_db.getAppServices(local_application._id):

        exists=False
        local_name = local_service.name

        for aosp_service in aosp_services:
            aosp_name = aosp_service.name

            if aosp_name == local_name:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            service_list.append(local_service)

    if len(service_list) != 0:
        printServices(service_list)

def diffProviders(local_db, local_application, aosp_db, aosp_application):

    provider_list = list()
    aosp_providers = aosp_db.getAppProviders(aosp_application._id)

    for local_provider in local_db.getAppProviders(local_application._id):

        exists=False
        local_name = local_provider.name

        for aosp_provider in aosp_providers:

            aosp_name = aosp_provider.name

            if aosp_name == local_name:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            provider_list.append(local_provider)

    if len(provider_list) != 0:
        printProviders(provider_list)

def diffReceivers(local_db, local_application, aosp_db, aosp_application):

    receiver_list = list()
    aosp_receivers = aosp_db.getAppReceivers(aosp_application._id)

    for local_receiver in local_db.getAppReceivers(local_application._id):

        exists=False
        local_name = local_receiver.name

        for aosp_receiver in aosp_receivers:
            aosp_name = aosp_receiver.name

            if aosp_name == local_name:
                exists=True
                break

        if not exists:
        # Getting here means we dont have it.
            receiver_list.append(local_receiver)

    if len(receiver_list) != 0:
        printReceivers(receiver_list)


def ddiffReceivers(project_db, project_app_id, aosp_db, aosp_app_id):

    receiver_list = list()

    sql = ('SELECT name, exported, enabled, permission, intent_data '
           'FROM receivers r '
           'WHERE application_id=%d' % project_app_id)

    for receiver in project_db.execute(sql):

         name = receiver[0]

         if not appHasReceiverInAOSP(aosp_db, aosp_app_id, name):

             exported = receiver[1]
             enabled = receiver[2]
             permission_id = receiver[3]
             permission_name = getPermissionName(project_db, permission_id)
             intent_data = b64decode(receiver[4])
             permission_protection_level = getPermissionProtectionLevel(project_db, permission_id)

             tmp_rvc = Receiver( name, enabled, exported,
                                 Permission(permission_name, permission_protection_level),
                                 intent_data)

             receiver_list.append(tmp_rvc)

    return receiver_list

def printPermissions(perm_list):

    print "[+] Permissions"
    for perm in perm_list:
        print "   %s" % str(perm)

def printUsesPermissions(uses_perm_list):

    print "[+] Uses Permissions"
    for uses_perm in uses_perm_list:
        print "   %s" % str(uses_perm)


def printActivities(activity_list):

    if len(activity_list) > 0:
        print "[+] Activities"
        i = 1
        for act in activity_list:
            print "  %d. %s" % (i, act.name)
            print "       Permission: %s" % str(act.permission)
            print "       Enabled: %s" % str(act.enabled)
            print "       Exported: %s" % str(act.exported)
            if len(act.intent_data) != 0:
                print "       Intent Data:"
                print "       %s" % str(act.intent_data)
            i+=1


def printServices(service_list):

    if len(service_list) > 0:
        print "[+] Services"
        i = 1
        for svc in service_list:
            print "  %d. %s" % (i, svc.name)
            print "       Permission: %s" % str(svc.permission)
            print "       Enabled: %s" % str(svc.enabled)
            print "       Exported: %s" % str(svc.exported)
            if len(svc.intent_data) != 0:
                print "       Intent Data:"
                print "       %s" % str(svc.intent_data)
            i+=1

def printProviders(provider_list):

    if len(provider_list) > 0:
        print "[+] Providers"
        i = 1
        for pvdr in provider_list:
            print "  %d. %s" % (i, pvdr.name)
            print "       Authorities: %s" % pvdr.authorities
            print "       Permission: %s" % str(pvdr.permission)
            print "       Read Permission: %s" % str(pvdr.read_permission)
            print "       Write Permission: %s" % str(pvdr.write_permission)
            print "       Enabled: %s" % pvdr.enabled
            print "       Exported: %s" % pvdr.exported

            if (pvdr.grant_uri_permissions != "false") or (pvdr.grant_uri_permissions != "None"):
                print "       Grant URI Permissions:"
                print "       <%s>" % pvdr.grant_uri_permissions

            if len(pvdr.path_permission_data):
                print "       Path Permissions:"
                print "       <%s>" % pvdr.path_permission_data

            i+=1

def printReceivers(receiver_list):

    if len(receiver_list) > 0:
        print "[+] Receivers"
        i = 1
        for rvc in receiver_list:
            print "  %d. %s" % (i, rvc.name)
            print "       Permission: %s" % str(rvc.permission)
            print "       Enabled: %s" % str(rvc.enabled)
            print "       Exported: %s" % str(rvc.exported)
            if len(rvc.intent_data) != 0:
                print "       Intent Data:"
                print "       %s" % str(rvc.intent_data)
            i+=1

# Main

aosp_db = None
project_db = None
display_filter = ""


if len(argv) > 2:
    display_filter = argv[2]

project_name = argv[1]

local_db_path = '.dbs/sysapps.db'
aosp_db_path = dtfglobals.DTF_PACKAGES + "/aosp-data-" + dtfconfig.get_prop("Info", "sdk") + "/dbs/sysapps.db"

local_db = AppDb.AppDb(local_db_path, safe=True)
aosp_db = AppDb.AppDb(aosp_db_path, safe=True)

local_application = local_db.getAppByName(project_name)

if local_application is None:
    print "Are you sure this application exists in your local DB? Exiting."
    exit(-4)

#print "got it, %d" % local_application._id

aosp_application = aosp_db.getAppByName(project_name)

if aosp_application is None:
    print "Are you sure this application exists in the AOSP DB? Exiting."
    exit(-4)

if display_filter == "permissions":
    diffPermissions(local_db, local_application, aosp_db, aosp_application)
    exit(0)

elif display_filter == "uses-permissions":
    diffUsesPermissions(local_db, local_application, aosp_db, aosp_application)
    exit(0)

elif display_filter == "activities":
    diffActivities(local_db, local_application, aosp_db, aosp_application)
    exit(0)

elif display_filter == "services":
    diffServices(local_db, local_application, aosp_db, aosp_application)
    exit(0)

elif display_filter == "providers":
    diffProviders(local_db, local_application, aosp_db, aosp_application)
    exit(0)

elif display_filter == "receivers":
    diffReceivers(local_db, local_application, aosp_db, aosp_application)
    exit(0)

else:
    # First do permission statements
    diffPermissions(local_db, local_application, aosp_db, aosp_application)

    # Now the use permissions
    diffUsesPermissions(local_db, local_application, aosp_db, aosp_application)

    # Components
    diffActivities(local_db, local_application, aosp_db, aosp_application)
    diffServices(local_db, local_application, aosp_db, aosp_application)
    diffProviders(local_db, local_application, aosp_db, aosp_application)
    diffReceivers(local_db, local_application, aosp_db, aosp_application)
    exit(1)
