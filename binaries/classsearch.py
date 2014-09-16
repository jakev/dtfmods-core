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
# Class searching support
from sys import argv
from os import listdir
from pydtf import dtfconfig
import sqlite3
import argparse

def searchDb(db_name, config):

    search_class_name = config['class_name']   
    search_method_name = config['method_name']
    show_fields = config['show_fields']
    show_methods = config['show_methods']
    field_contains = config['field_contains']
    file_mode = config['file_mode']
    exact = config['exact']

    method_search = False

    #print "doing : %s" % (db_name)
    class_list = list()
   
    #print search_class_name, search_method_name

    if search_method_name is not None:
        method_search = True

    conn = sqlite3.connect(db_name)

    c = conn.cursor()

    sql = ('SELECT id, name, access_flags, superclass '
           'FROM classes')

    for class_id, class_name, access_flags, superclass in c.execute(sql):

        if method_search:

            mc = conn.cursor()
            msql = ("SELECT name FROM methods where class_id=%d" % class_id)
            
            for method_name in mc.execute(msql):

                if method_name[0] == search_method_name:
                    print "   %s->%s" % (class_name,method_name[0])
        else:
            if exact:
                if class_name == search_class_name:
                    class_list.append( class_name )
            else:
                if class_name.find(search_class_name) != -1:
                    class_list.append( class_name )

    if not method_search and len(class_list) != 0:
        if not file_mode: print "[+] In database: %s" % (db_name)
        for n in class_list:
            if file_mode:
                framework_file = db_name.replace(".dbs/frameworkdexdbs/","").replace(".db","")
                unframework_dir = dtfconfig.get_prop("Local", "unframework-dir")
                dotted_path = n.replace(".","/")
                print "%s/%s/%s.smali" % (unframework_dir, framework_file, dotted_path)
            else:
                print "\t%s" % (n)
            if show_fields:
                fsql = ("SELECT sf.name FROM static_fields sf JOIN classes c ON c.id=sf.class_id WHERE c.name='%s'" % n)

                for field_name in c.execute(fsql):

                    if field_name[0].find(field_contains) != -1:
                        print "\t  +%s" % field_name[0]





config = dict()
class_name = None
method_name = None

parser = argparse.ArgumentParser(description='Search for a class name.')
parser.add_argument('search_class', type=str, help='Class to search for.', nargs='?', 
                    default=None)
parser.add_argument('--frameworks', dest='fw', action='store_const',
                    const=True, default=False,
                    help='Search framework files.')
parser.add_argument('--apps', dest='app', action='store_const',
                    const=True, default=False,
                    help='Search application files.')
parser.add_argument('-e', dest='exact', action='store_const', const=True, default=False,
                    help='Match exact name.')
parser.add_argument('-f', dest='file_mode', action='store_const', const=True, default=False,
                    help='Print path to file instead.')
parser.add_argument('--hasMethod', dest='has_method', help='Search by method name.')
parser.add_argument('--implements', dest='implements', default=None, 
                    help='Search by implemented class')
parser.add_argument('--fields', dest='show_fields', action='store_const', const=1, default=0,
                    help='Display fields for matching class')
parser.add_argument('--methods', dest='show_methods', action='store_const', const=1, default=0,
                    help='Display methods for matching class')
parser.add_argument('--fieldContains', dest='field_contains', default=None,
                    help='Filter fields')

args = parser.parse_args()

search_frameworks = args.fw
search_apps = args.app

if search_frameworks == False and search_apps == False:
    print "[ERROR] You need to specify either '--frameworks' or '--apps'!"
    exit(-2)

method_name = args.has_method
class_name = args.search_class
show_methods = args.show_methods
show_fields = args.show_fields
field_contains = args.field_contains
exact = args.exact
file_mode = args.file_mode

config['method_name'] = method_name
config['class_name'] = class_name
config['show_methods'] = show_methods
config['show_fields'] = show_fields
config['field_contains'] = field_contains
config['file_mode'] = file_mode
config['exact'] = exact

if class_name is None and method_name is None:
    print "You need to specify a class_name to search for!"
    exit(2)

db_dir = dtfconfig.get_prop("Local", "db-dir")

if search_frameworks:
    # For file in frameworkdexdbs
    try:
        for db in listdir(db_dir+"/frameworkdexdbs/"):
            searchDb(db_dir+"/frameworkdexdbs/"+db, config)
    except OSError:
        print "[ERROR] Error listing framework DEX databases, do they exist?"
        exit(-4)

if search_apps:
    # For file in appdexdbs
    try:
        for db in listdir(db_dir+"/appdexdbs/"):
            searchDb(db_dir+"/appdexdbs/"+db, config) 
    except OSError:
        print "[ERROR] Error listing app DEX databases, do they exist?"
        exit(-4)
