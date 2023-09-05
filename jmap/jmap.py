'''
 The MIT License (MIT)

 Copyright (c) 2016 Ian Van Houdt

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
'''

############
#
#  jmap.py
#
#  Serves as the jmap library for the sse client/server.
#  Both client and server will use this lib to create 
#  and interpret JMAP messages
#
############

import json

FILE = "[JMAP] "
SEARCH = "search"
SEARCH_DOC = "search_doc"
UPDATE = "update"
ADD_FILE = "add"
SEARCH_METHOD = "getDecryptedSegments"
SEARCH_DOC_METHOD = "getEncryptedMessages"
UPDATE_METHOD = "updateEncryptedIndex"
ADD_FILE_METHOD = "putEncryptedMessage"

JMAP_HEADER = {'Content-Type': 'application/json'} 

# Notes on JMAP spec from jmap.io/spec
'''
BASIC QUERY STRUCTURE:
[
  ["method1", {"arg1": "arg1data", "arg2": "arg2data"}, "#1"],
  ["method2", {"arg1": "arg1data"}, "#2"],
  ["method3", {}, "#3"]
]

BASIC RESPONSE STRUCTURE:
[
  ["responseFromMethod1", {"arg1": 3, "arg2": "foo"}, "#1"],
  ["responseFromMethod2", {"isBlah": true}, "#2"],
  ["anotherResponseFromMethod2", {"data": 10, "yetmoredata": "Hello"}, "#2"],
  ["aResponseFromMethod3", {}, "#3"]
] 

EXAMPLE REQ:
["getMessages", {
  "ids": [ "f123u456", "f123u457" ],
  "properties": [ "threadId", "mailboxIds", "from", "subject", "date" ]
}, "#1"]

EXAMPLE RESP:
["messages", {
  "state": "41234123231",
  "list": [
    {
      messageId: "f123u457",
      threadId: "ef1314a",
      mailboxIds: [ "f123" ],
      from: [{name: "Joe Bloggs", email: "joe@bloggs.com"}],
      subject: "Dinner on Thursday?",
      date: "2013-10-13T14:12:00Z"
    }
  ],
  notFound: [ "f123u456" ]
}, "#1"]

========

JMAP CALLS FOR SSE:

["method", {args}, "id"]

["getEncryptedMessages", 
  {
  "query": [ "(k1 n, k2 n)", "(k1 n+1, k2 n+1)", ... ]
  },
  "#1" ]

["encryptedMessages",
  {
  "results": [ "data for msg n", "data for msg n+1", ... ]
  }
  "#1" ]

  -NOTE: for returning enc messages, possbility exists for returning each
         message's data in a separate message. Just reuse id num

'''

def jmap_header():
    return JMAP_HEADER

def pack_search_doc(data):
    return json.dumps([SEARCH_DOC_METHOD, {"query": data}])
    
def pack_search(data, id_num, cluster_id):
    id_num = json.dumps(id_num)
    cluster_id = json.dumps(cluster_id)
    return json.dumps([SEARCH_METHOD, {"query": data}, id_num, cluster_id])

def pack_update_index(data, id_num, cluster_id):
    return json.dumps([UPDATE_METHOD, {"index": data}, id_num, cluster_id])

def pack_add_file(data, id_num, filename):
    return json.dumps([ADD_FILE_METHOD, {"file": data.decode(), "filename": filename}, id_num])

def pack(METHOD, data, id_num=None, filename=None):
    FUNC = "jmap.pack"
    message = None

    if not METHOD:
        print(FILE + "Must provide a method to " + FUNC)
        return -1

    if METHOD == SEARCH:
        cluster_id = filename
        message = pack_search(data, id_num, cluster_id)
    
    elif METHOD == SEARCH_DOC:
        message = pack_search_doc(data)

    elif METHOD == UPDATE:
        cluster_id = filename
        message = pack_update_index(data, id_num, cluster_id)

    elif METHOD == ADD_FILE:
        message = pack_add_file(data, id_num, filename)

    else:
        print(FILE + "Unknown METHOD in " + FUNC)
        return -1

    return message

def unpack_search(data):

    if data[0] != SEARCH_METHOD:
        return -1

    method = data[0]
    id_num = json.loads(data[2])
    cluster_id = json.loads(data[3])

    # Limit scope to args (data[1])
    data = data[1]
    query = data['query']

    return (method, query, id_num, cluster_id)

def unpack_search_doc(data):
    if data[0] != SEARCH_DOC_METHOD:
        return -1
    method = data[0]
    query = data[1]['query']
    return (method, query)

def unpack_update(data):
    
    if data[0] != UPDATE_METHOD:
        return -1

    method = data[0]
    id_num = data[2]
    cluster_id = data[3]

    # Limit scope to args (data[1])
    data = data[1]
    new_index = data['index']

    return (method, new_index, id_num, cluster_id)

def unpack_add_file(data):

    if data[0] != ADD_FILE_METHOD:
        return -1

    method = data[0]
    id_num = data[2]

    # Limit scope to args (data[1])
    data = data[1]

    file = data['file']
    filename = data['filename']

    return (method, file, filename, id_num)

def unpack(METHOD, data):
    FUNC = "jmap.unpack"

    if not METHOD:
        print(FILE + "Must provide a method to " + FUNC)
        return -1
  
    if METHOD == SEARCH:
        return unpack_search(data)
    elif METHOD == SEARCH_DOC:
        return unpack_search_doc(data)
    elif METHOD == UPDATE:
        return unpack_update(data)
    elif METHOD == ADD_FILE: 
        return unpack_add_file(data)
    else:
        print(FILE + "Unknown METHOD in " + FUNC)
        return -1


