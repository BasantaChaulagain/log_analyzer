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
#  sse_client.py
#
#  Serves as SSE implementation for client. The routines 
#  for SSE are invoked by the client module via the API.
#
############

import sqlite3
from requests.api import get
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from datetime import datetime
import bcrypt
import binascii
import string
import dbm
from flask import Flask, jsonify, request
import requests
from nltk.stem.porter import PorterStemmer
import os
import json
import re
import inspect
import sys
import shutil
from time import time

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from jmap import jmap
from client.file_handler import FileHandler
from client.log_handler import variable_schema, LogHandler

DEBUG = 1
SEARCH = "search"
SEARCH_DOC = "search_doc"
UPDATE = "update"
ADD = "add"

CSV_INPUT = 1

# Default url is localhost, and the port 5000 is set by Flask on the server
DEFAULT_URL = "http://127.0.0.1:5000/"

NO_RESULTS = "Found no results for query"

DELIMETER = "++?"

# TODO: Maybe strip out some of the excluded punctuation. Could be useful
# to keep some punct in the strings. We're mostly looking to strip the
# final punct (ie: '.' ',' '!' etc)
EXCLUDE = string.punctuation

def get_schema_id(var):
    for key, value in variable_schema.items():
        match = re.fullmatch(value, var)
        if match:
            return(str(key))
    return None


def get_lookup_table():
    try:
        with open('ltdict.json', 'r') as f:
            ltdict = json.load(f)
        with open('vdict.json', 'r') as f:
            vdict = json.load(f)
        lookup_table = [ltdict, vdict]
    except:
        lookup_table = [{},{}]
    return lookup_table


def get_cluster_id(word, schema_id):
    cluster_ids = []
    try:
        with open('vdict.json', 'r') as f:
            vdict = json.load(f)

        for key, value in vdict.items():
            for each in value.get(schema_id).values():
                if each[0] == word:
                    cluster_ids.append(key)
        return cluster_ids
    except:
        return cluster_ids


########
#
# SSE_Client
#
########
class SSE_Client():

    def __init__(self):

        # TODO: placeholder for password. Will eventually take
        # as an arg of some sort
        self.password = b"password"

        # TODO: need to sort out use of salt. Previously, salt was
        # randomly generated in initKeys, but the resulting pass-
        # words k & kPrime were different on each execution, and 
        # decryption was impossible. Hardcoding salt makes dectyption
        # possible but may be a bad short cut
        self.iv = None
        self.salt = b"$2b$12$ddTuco8zWXF2.kTqtOZa9O"

        # Two keys, generated/Initialized by KDF
        (self.k, self.kPrime) = self.initKeys()

        # Two K's: generated/initialized by PRF
        self.k1 = None
        self.k2 = None

        # client's cipher (AES w/ CBC)
        self.cipher = self.initCipher()

        # Stemming tool (cuts words to their roots/stems)
        self.stemmer = PorterStemmer()
        self.db = self.ensure_metadata_db()

    def initKeys(self):
        # initialize keys k & kPrime
        # k used for PRF; kPrime used for Enc/Dec
        # return (k, kPrime)

        #hashed = bcrypt.hashpw(self.password, bcrypt.gensalt())
        hashed = bcrypt.hashpw(self.password, self.salt)

        if(DEBUG > 1):
            print(("len of k = %d" % len(hashed)))
            print(("k = %s" % hashed))

        # Currently k and kPrime are equal
        # TODO: Sort out requirements of k and kPrime
        # Research uses both, but not sure the difference
        return (hashed, hashed)


    def initCipher(self):
        # initialize Cipher, using kPrime
        # return new Cipher object

        # TODO: fix key. Currently just a hack: AES keys must be
        # 16, 24 or 32 bytes long, but kPrime is 60
        key = self.kPrime[:16]

        # generates 16 byte random iv
        self.iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, self.iv)

        return cipher

    def ensure_metadata_db(self):
        db = sqlite3.connect('metadata')
        db.execute('''CREATE TABLE IF NOT EXISTS SEGMENT_INFO (file_id text, segment_id text, cluster_id text, ts_start real, ts_end real)''')
        if db == None:
            print("Error while opening database")
        return db
        
        
    def encryptSegment(self, infile, outfile):

        # read in infile (opened file descriptor)
        buf = infile.read()
        if buf == '': 
            print("[Enc] segment to encrypt is empty!\nExiting\n")
            exit(1)

        # pad to mod 16
        while len(buf)%16 != 0:
            buf = buf + "\x08"

        # write encrypted data to new file
        outfile.write((self.iv + self.cipher.encrypt(buf.encode('latin1'))))


    def decryptSegment(self, buf, outfile=None):
        # Just pass in input file buf and fd in which to write out
        if buf == '': 
            print("[Dec] segment to decrypt is empty!\nExiting\n")
            exit(1)
        
        if type(buf) == str:
            buf = buf.encode('latin1')

        # self.kPrime[:16] is the  first 16 bytes of kPrime, ie: enc key
        # buf[:16] is the iv of encrypted msg

        # pad to mod 16
        while len(buf)%16 != 0:
            buf = buf + b"\x08"

        cipher = AES.new(self.kPrime[:16], AES.MODE_CBC, buf[:16])

        # decrypt all but first 16 bytes (iv)
        # if outfile is supplied, write to file
        if (outfile):
            outfile.write((cipher.decrypt(buf[16:])).decode('latin1'))
        # else print to terminal
        else:
            tmp = cipher.decrypt(buf[16:])
            return(tmp.decode('latin1'))


    def encryptSegmentID(self, k2, segment_ids):

        # Encrypt doc id (document) with key passed in (k2)

        # set up new cipher using k2 and random iv
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(k2[:16].encode('latin1'), AES.MODE_CBC, iv)

        # pad to mod 16
        while len(segment_ids)%16 != 0:
            segment_ids = segment_ids + '\x08'

        encId = iv + cipher.encrypt(segment_ids.encode('latin1'))

        if (DEBUG > 1):
            print(("New ID for '%s' = %s" % 
                 (segment_ids, (binascii.hexlify(encId)))))

        return binascii.hexlify(encId)


    def update(self, filename):
        begin_ts = datetime.now()
        
        file = FileHandler(filename)
        segments = file.split_file()
        file.encode_logs()
        lookup_table = file.get_lookup_table()
        
        encode_ts = datetime.now()

        # First update index and send it
        print("updating the index")
        (indexes, update_idx_ts) = self.update_index(lookup_table)

        for index in indexes:
            # ((index, vdict_id. cluster_id))
            message = jmap.pack(UPDATE, index[0], index[1], index[2])
            # print(message)
            r = self.send(UPDATE, message)
            if(type(r) != dict):
                r = r.json()
            results = r['results']
            print("Results of Index UPDATE: " + results) 
            
        encrypt_idx_ts = datetime.now()
        
        # Then encrypt msg
        for seg in segments:
            print("Encrypting segment: ", seg)
            infile = open(seg, "r") 
            outfilename_ = seg.split('/')[1]
            outfilename = "enc/" + outfilename_
            outfile = open(outfilename, "wb+")
            self.encryptSegment(infile, outfile)
            infile.close()
    
            outfile.seek(0)
            data = binascii.hexlify(outfile.read())
            message = jmap.pack(ADD, data, "1", outfilename_)

            # Then send message
            r = self.send(ADD, message, outfilename)        
            if(type(r) != dict):
                r = r.json()
            results = r['results']
            print("Results of UPDATE/ADD FILE: " + results)

            outfile.close()

        for f in os.listdir("tmp/"):
            os.remove(os.path.join("tmp/", f))
        
        encrypt_ts = datetime.now()
        
        print("\nStats (time required):")
        print("Encode segments: {}\nUpdate index: {}\nEncrypt index: {}\nEncrypt segments: {}\n"
              .format(encode_ts-begin_ts, update_idx_ts-encode_ts, encrypt_idx_ts-update_idx_ts, encrypt_ts-encrypt_idx_ts))
        print("Encoding: {}\nEncrypting: {}\nTotal: {}".format(update_idx_ts-begin_ts, encrypt_ts-update_idx_ts, encrypt_ts-begin_ts))


    def update_index(self, lookup_table):
        vdict = lookup_table[1]
        for k, v in vdict.items():
            cluster_id = k
            key = "9"   # variable schema for integer
            integer_dict = v.get(key)
            index = dbm.open("indexes/"+cluster_id+"_index_"+key, "c")
            index_IDs = dbm.open("indexes/"+cluster_id+"_index_IDs_"+key, "c")

            vdict_items = list(integer_dict.values())
            for item in vdict_items:
                # sample item: ['DAEMON_START', 2, ['bYvf8pWtahZSNwiVMs7M8g']]
                if item[0] not in index.keys():
                    index[item[0]] = str(item[1])
                else:
                    if item[1] != int(index.get(item[0])):
                        index[item[0]] = str(item[1])

                if item[0] not in index_IDs.keys():
                    index_IDs[item[0]] = DELIMETER.join(item[2])
                else:
                    if int(item[1]) != index.get(item[0]):
                        index[item[0]] = DELIMETER.join(item[2])
            
            index.close()
            index_IDs.close()
            
        update_idx_ts = datetime.now()

        indexes = []
        for k,v in vdict.items():
            cluster_id = k
            key = "9"   # variable schema for integer

            ind = "indexes/"+cluster_id+"_index_"+key
            ind_id = "indexes/"+cluster_id+"_index_IDs_"+key
            index = self.encryptIndex(ind, ind_id)
            indexes.append((index, int(key), cluster_id))
            
        return (indexes, update_idx_ts)


    def encryptIndex(self, index, index_IDs):

        # This is where the meat of the SSE update routine is implemented

        L = []
        index = dbm.open(index, "r")
        index_IDs = dbm.open(index_IDs, "r")
       
        # For each word, look through local index to see if it's there. If
        # not, set c = 0, and apply the PRF. Otherwise c == number of 
        # occurences of that word/term/number 

        for word in index.keys():
            if type(word) == bytes:
                word = word.decode()
            count = index[word]
            if type(count) == bytes:
                count = count.decode()
            # Initialize K1 and K2
            k1 = self.PRF(self.k, ("1" + word))
            k2 = self.PRF(self.k, ("2" + word))
 
            # Set l as the PRF of k1 (1 || w) and c (num of occur) if parsing the body            
            l = self.PRF(k1, count)
            lprime = self.PRF(k1, str(int(count)-1))

            segment_ids = index_IDs[word].decode()
            d = self.encryptSegmentID(k2, segment_ids).decode()

            L.append((l, d, lprime))

        index.close()
        index_IDs.close()

        return L


    def search(self, query, base_ts=0, search_type=''):
        return_result = ""
        return_result += "metainfo: %s\n" % time()

        # Generate list of querys (may be just 1)
        L = []
        ids = []
        word = query.lower()
        
        schema_id = get_schema_id(word)
        ids.append(schema_id)
        cluster_ids = get_cluster_id(word, schema_id)
        
        for cid in cluster_ids:
            index_file = "indexes/"+cid+"_index_"+schema_id
            if (os.path.exists(index_file)):
                index = dbm.open(index_file, "r")
            else:
                return_result += "Search keyword not found\n"
                return return_result

            # For each term of query, first try to see if it's already in
            # index. If it is, send c along with k1 and k2. This will 
            # massively speed up search on server (1.5 minutes to < 1 sec)
            try:
                c = index[word]
            except:
                c = None

            # Use k, term ('i') and '1' or '2' as inputs to a pseudo-random
            # function to generate k1 and k2. K1 will be used to find the 
            # correct encrypted entry for the term on the server, and k2
            # will be used to decrypt the mail ID(s)
            k1 = self.PRF(self.k, ("1" + word))

            # If no 'c' (term not in local index so likely not on server),
            # just send k1 and k2. Will take a long time to return false
            # TODO, should the client just kill any search for a term not
            # in local index?  Can we rely on the local index always being
            # up to date?
            if not c:
                L.append((k1))
            # Otherwise send along 'c'. 
            else:
                c = str(int(c))
                L.append((k1, c))
            
        k2 = self.PRF(self.k, ("2" + word)).encode('latin1', 'ignore')    
        
        message = jmap.pack(SEARCH, L, ids, cluster_ids)
        # Send data and unpack results.
        ret_data = self.send(SEARCH, message)

        segments_e = ret_data['results']
        segments_d = []
        
        for each in segments_e:
            m_str = ''
            m = self.dec(k2, each).decode()
            for x in m:
                if x in string.printable:
                    m_str += x
            for msg in m_str.split(DELIMETER):
                if msg not in segments_d:
                    segments_d.append(str(msg))
                
        cur = self.db.cursor()
        if search_type == 'f':
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start<=? and ts_end>=?''', (base_ts, base_ts))
            base_segment = [list[0] for list in cur.fetchall()]
            if len(base_segment) >= 1:
                base_segment = base_segment[0]
                cur.execute('''SELECT ts_start FROM SEGMENT_INFO WHERE segment_id=?''', (base_segment, ))
                base_ts = cur.fetchone()[0]
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start>=?''', (base_ts, ))
            relevant_segments = [list[0] for list in cur.fetchall()]
        
        elif search_type == 'b':
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start<=? and ts_end>=?''', (base_ts, base_ts))
            base_segment = [list[0] for list in cur.fetchall()]
            if len(base_segment) >= 1:
                base_segment = base_segment[-1]
                cur.execute('''SELECT ts_end FROM SEGMENT_INFO WHERE segment_id=?''', (base_segment, ))
                base_ts = cur.fetchone()[0]
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_end<=?''', (base_ts, ))
            relevant_segments = [list[0] for list in cur.fetchall()]
        
        return_segments = []
        for each in segments_d:
            if each in relevant_segments:
                return_segments.append(each)
                
        message = jmap.pack(SEARCH_DOC, return_segments)
        ret_data = self.send(SEARCH_DOC, message)
        
        if(type(ret_data) != dict):
            ret_data = ret_data.json()
        results = ret_data['results']
        return_result += "Results of SEARCH:\n"
        
        if results == NO_RESULTS:
            return_result += "%s\n" % results
            return return_result

        decoded_message = ''''''
        for i in results:
            decrypted = self.decryptSegment(i.encode('latin1'), )
            lookup_table = get_lookup_table()
            decrypted_ = decrypted.split('\n')[:-1]
            for cid in cluster_ids:
                l = LogHandler(lookup_table, cid)
                for each in decrypted_:
                    decoded = l.decode(each)
                    if re.search(r'\b{}\b'.format(word), decoded):
                        decoded_message += (decoded+'\n')
        
        return_result += "metainfo: %s\n" % time()
        return_result += "%s" % decoded_message
        return(return_result)

    def PRF(self, k, data):
        if type(data) == str:
            data = data.encode('latin1')
        if type(k) == str:
            k = k.encode('latin1')
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()

    # Decrypt doc ID using k2
    def dec(self, k2, d):
        d_bin = binascii.unhexlify(d) 
        iv = d_bin[:16]
        cipher = AES.new(k2[:16], AES.MODE_CBC, iv)
        doc = cipher.decrypt(d_bin[16:])

        return doc

    def send(self, routine, data, filename = None, in_url = DEFAULT_URL):
        # print("sending to ", in_url)
        url = in_url

        # Currently, each server url is just <IP>/<ROUTINE>, so just append
        # routine to url, and set up headers with jmap package.

        if routine == SEARCH:
            url = url + SEARCH
            headers = jmap.jmap_header()
        elif routine == SEARCH_DOC:
            url = url + SEARCH_DOC
            headers = jmap.jmap_header()
        elif routine == UPDATE:
            url = url + UPDATE
            headers = jmap.jmap_header()
        elif routine == ADD:
            url = url + ADD
            # For sending mail, need to do a little extra with the headers
            headers = {'Content-Type': 'application/json',
                       'Content-Disposition': 
                       'attachment;filename=' + filename}
        else:
            print("[Client] Error: bad routine for send()")
            exit(1)

        if (DEBUG > 1): 
            print(url)

        # Send to server using requests's post method, and return results
        # to calling method
        client_out_time = time()
        result = requests.post(url, data, headers = headers)
        client_in_time = time()
        result_json = result.json()
        if(len(result_json['results'])>1 and type(result_json['results']) == list and type(result_json['results'][-1]) == float):
            server_out_time = result_json['results'].pop()
            server_in_time = result_json['results'].pop()
            # print("client-to-server:", float(server_in_time)-client_out_time)  # n/w delay when sending
            # print("server-to-client:", client_in_time-float(server_out_time))  # n/w delay when receiving
        return (result_json)
