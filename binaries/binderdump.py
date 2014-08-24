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
# Binder Interface Dumper
import re
from sys import argv

def generateParamString(params, param_names):

   if params == "" or param_names is None:
       return ""

   args_n = len(param_names)
   print "len",args_n
   if args_n == 1:
       return "%s %s" % (params, param_names[0])


if len(argv) != 2:
    print "Usage: %s base_path" % "binderdump"
    exit(-3)

base_path = argv.pop()

stub_file_path = base_path + "$Stub.smali"
proxy_file_path = base_path + "$Stub$Proxy.smali"


# First do the Stub.smali
smali_f = open(stub_file_path, "r")

binder_list = list()

for line in smali_f.read().split("\n"):

    if line.find(".field static final TRANSACTION_") != -1:

       reduced = line[32:].replace(":I = ","|").split("|")

       binder_interface = reduced[0]
       binder_number = int(reduced[1], 16)

       binder_list.append( (binder_number, binder_interface) )




binder_list = sorted(binder_list,key=lambda x: x[0])


# Now lets do the Stub.Proxy.smali
proxy_f = open(proxy_file_path, "r")

data = proxy_f.read()

for binder in binder_list:

    param_names = list()
 
    binder_number = binder[0]
    binder_interface = binder[1]
    regex = re.compile(".method public "+binder_interface+".*?\.prologue", re.DOTALL)
   
    try:
        prologue_block = re.findall(regex, data)[0].split("\n")
    except IndexError:
        print "[Warning] Binder interface for '%s' not found, skipping" % binder_interface
        continue

    sig = prologue_block[0].replace(".method public "+binder_interface, "")

    params = sig.split(')')[0].replace('(', "")
    return_type = sig.split(')')[1]

    if params != "":
        for line in prologue_block:
            if line.find("    .parameter ") != -1:
               param_names.append(line.split('"')[1])

    print "%i %s(%s)" % (binder_number, binder_interface, params)

    for param in param_names: print "   Parameter: \"%s\"" % param
 
    print "   Returns: %s" % (return_type)
