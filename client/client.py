############
#
#  client.py
#
#  Serves as SSE implementation for mail client. The routines 
#  for SSE are invoked by the client module via the API.
#
############

from argparse import ArgumentParser
import dbm
import urllib
import os
import inspect
import sys
import yaml
import socket

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from client.sse_client import CSV_INPUT, SSE_Client

# CONFIG_FILE = "../config.yml"
# config = {}
# with open(CONFIG_FILE, 'r') as ymlfile:
#     config = yaml.safe_load(ymlfile)

DEBUG = 1
CSV_INPUT = 1
# CSV_INPUT = config["GLOBAL"]["CSV_INPUT"]

def sse_search(keyword, base_ts, type):
    sse = SSE_Client()
    return(sse.search(keyword, base_ts, type))

def main():
    # Set-up a command-line argument parser

    # TODO: Fix argument parser. It works for what it is, but I don't 
    # have a good enough grasp of the argparser package to fine tune it 
    # ie: some options shouldnt require an argument but do (ie: '-i' 
    # should be a standalone option, but currently requires a following,
    # unused argument

    parser = ArgumentParser()
    parser.add_argument('-s', '--search', metavar='search', dest='search',
                        nargs='*')
    parser.add_argument('-u', '--update', metavar='update', dest='update',
                        nargs=1)
    parser.add_argument('-i', '--inspect_index', dest='inspect_index')
    parser.add_argument('-c', '--csv_input', dest='csv_input')
    parser.add_argument('-t', '--test_http', dest='test_http')
    args = parser.parse_args()
 
    sse = SSE_Client()

    if args.csv_input:
        CSV_INPUT = 1

    if args.update:
        if (DEBUG):
            print(("Updating index with document %s" % args.update[0]))
        filename = args.update[0]
        sse.update(filename)

    elif args.search:
        if (DEBUG):
           print(("Searching remote index for word(s): '%s'" 
                  % args.search[0]))
        res = sse.search(args.search[0], args.search[1], args.search[2])
        print(res)

    elif args.inspect_index:
        if (DEBUG): print("Inspecting the index")
        indexes = os.listdir('indexes')
        for index in indexes:
            index_ = dbm.open('indexes/'+index, "r")
            print("\n------"+index+"------")
            for k in index_.keys():
                print("k:%s\tv:%s" % (k, index_[k]))
            index_.close()

    elif args.test_http:
        url = "http://localhost:5000/search"
        k1 = "c18d3a0d0a6278ee206447b13cbb46f182c7bb5d038398887a9506e673a1c016"
        k2 = "ccb215ad2018660ad49668bca3c7f4222dc737f2346bf9853d06917d77771655"
        k = []
        k.append(k1)
        k.append(k2)
        #values = { 'k1' : k1, 'k2' : k2 }
        values = { 'query' : k }
        data = urllib.parse.urlencode(values).encode("utf-8")
        req = urllib.request.Request(url, data)  
        response = urllib.request.urlopen(req)
        data = response.read()
        print(data)

    else:
        print("Must specify a legitimate option")
        exit(1)


if __name__ == "__main__":
    main()
