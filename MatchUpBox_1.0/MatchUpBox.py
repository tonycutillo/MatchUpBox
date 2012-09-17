#!/usr/bin/env python

# MatchUpBox: a privacy preserving online social network.
# Copyright (C) 2012 MatchUpBox <http://www.matchupbox.com>

# This file is part of MatchUpBox.

# MatchUpBox is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import loggin_tis

import random
import sys, os
import logging
import constants
import traceback
import Managers.Matryoshka
import time
import functions
import Managers.datamanager as datamanager
import hashlib
import threading
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join



welcome = """
================================================
              Welcome to MatchUpBox
================================================
* Type 'h' to see a brief help on the available commands
"""

help = """
* Help:
    help,  h: help
    quit,  q: quit

====Social Network overlay===========================
	frt    : Friend Table 
    mrm    : Matryoshka Routing Map
    isf   : Manually set Friendship Established

	
====Peer to Peer overlay=============================
    find, f: find a p2p value
    cont, c: p2p contacts
    data, d: p2p data stored
          w: watch internal p2p variables
    store,st: store key-value pair in the p2p net 
    ustor,ust: delete key-value pair in the p2p net """
    
def console(dispatcher):
    running = True
    print welcome
    cmd = ''
    while running:
        cmd = raw_input("SBPrompt > ").lower()
        if cmd in ('q', 'quit'):
            running = False
        elif cmd in ('h', 'help'):
            print help
        elif cmd in ('b', 'bor'):
            dispatcher.mat.sendBOR(log.CN[0],log.CN[1],log.CN[2],log.proplist)
        elif cmd in ('prs', 'profile_store'):
            print "* Type the post >",
            word = sys.stdin.readline().strip().lower()
            rnd = random.randint(0,10000)
            content = [9, rnd, 2, word, 3, True ,10]
            item = ["PST", content]
            dispatcher.mat.add(Job("R_MAT_PRS", item))
            #item = ["PPI", [5, 1, "PIPPO", "M", 0, 10]]
            #dispatcher.mat.add(Job("R_MAT_PRS", item))
        elif cmd in ('prr', 'profile_retrival'):
            print "* Type the contact's name >",
            word = sys.stdin.readline().strip().lower()
            dispatcher.mat.add(Job("R_MAT_PRR", word))
        # P2P commands (TEMP)
        elif cmd in ('c', 'cont'):
            dispatcher.p2p._printContacts()
        elif cmd in ('d', 'data'):
            dispatcher.p2p._printStoredData()
        elif cmd in ('fip', 'findIP'):
            def showValue(result):
                print "* FOUND:"
                for r in result:
                    print 'id='+str(r.id) + str('IP =')+' ('+r.address+' '+r.tcp_port+' '+r.udp_port+')'
                       
            def valueNotFound(result):
                print "# Value not found!"    
            print "* Type the keyword to search >",
            word = sys.stdin.readline().strip().lower()
            df = dispatcher.p2p.iterativeFind(word)
            df.addCallback(showValue)
            df.addErrback(valueNotFound)
        elif cmd in ('f', 'find'):
            def showValue(result):
                print "* FOUND:", result
                       
            def valueNotFound(result):
                print "# Value not found!"    
            print "* Type the keyword to search >",
            word = sys.stdin.readline().strip().lower()
            df = dispatcher.p2p.recursiveFind(word)
            df.addCallback(showValue)
            df.addErrback(valueNotFound)
        elif cmd in ('w'):
            dispatcher.p2p._watch()
        elif cmd in ('frt'):
             dispatcher.mat.printFRT()
        elif cmd in ('isf'):
             dispatcher.mat.setFRest()
        elif cmd in ('rmf'):
             dispatcher.mat.remFriendbyName()
        elif cmd in ('mrm'):
             dispatcher.mat.printMRM()
        elif cmd in ('st', 'store'):
            print "* Type \"[key] [value]\" to store >",
            word = sys.stdin.readline().strip().lower()
            words=word.split()
            if (len(words) == 2):
                hash = hashlib.sha1()
                hash.update(words[0])   
                dispatcher.p2p.publishData(hash.digest(),words[1])
            else:
                print "You must give a <key, value> pair"
        elif cmd in ('ust', 'ustor'):
            print "* Type \"[key] [value]\" to remove >",
            word = sys.stdin.readline().strip().lower()
            words=word.split()
            if (len(words) == 2):
                hash = hashlib.sha1()
                hash.update(words[0])   
                dispatcher.p2p.unpublishData(hash.digest(),words[1])
            else:
                print "You must give a <key, value> pair"
        elif cmd in ('th', 'threads'):
            print threading.enumerate( )
        #elif cmd in ('p', 'ping'):
        #    for i in range(len(dispatcher.p2p._routingTable._buckets)):
        #        for contact in dispatcher.p2p._routingTable._buckets[i]._contacts:
        #            dispatcher.p2p.ping(contact.id)
        #elif cmd in ('rmv'):
        #    print "* Type the uid >",
        #    uid = sys.stdin.readline().strip('\n').lower()
        #    
        #    dispatcher.mat.removeFriend(uid.decode('hex'))    
        else:
            print "# Unknown command"
    #dispatcher.close()
    #dispatcher.mat.close()
    #dispatcher.p2p.close()
    #dispatcher.mat._save_objects()
    #kill all threads and exit
    #!IMPORTANT NOTE: Since only profile retrieval threads are the pending threads
    #    it is not important to kill them. But if in the future, some periodically called
    #    threads are added to the system, then it is needed to check whether killing them
    #    is safe or not.
    #os._exit(1)
    #sys.exit(1)

def create_self_signed_cert(cert_dir):
    """
    If datacard.crt and datacard.key don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.
    """
    CERT_FILE = "cert.pem"
    KEY_FILE = "pkey.pem"
    if not exists(join(cert_dir, CERT_FILE)) or not exists(join(cert_dir, KEY_FILE)):

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "EU"
        cert.get_subject().ST = "this"
        cert.get_subject().L = " =this"
        cert.get_subject().O = "this"
        cert.get_subject().OU = "this"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(join(cert_dir, CERT_FILE), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, KEY_FILE), "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))	
	
	
if __name__ == '__main__':
    logging.basicConfig(
            filename = "log"+os.sep+"sb.log",
            filemode = 'w',
            format   = "%(threadName)-17s - %(asctime)s: - %(message)s",
            level    = logging.DEBUG)
    fr=False
    if not functions.checkUid():
        fr=True
        #TONY
        name,surname,sex,dateofborn,city,nation, avatar_location ,K, pwd,tisadd, tisport=loggin_tis.user_arguments()
        log=loggin_tis.loggin_tis((name.lower(),surname.lower(),sex.lower(),dateofborn.lower(),city.lower(),nation.lower()), K, pwd,tisadd, tisport,avatar_location )
		
        #log=loggin_tis.loggin_tis(("frank","coral","male","01/01/2011","brasilia","bra"), functions.retrive_K("frank"), "frank","192.168.104.90", "4003","avatar.jpg")
        log.getCertificate()

    create_self_signed_cert('mypem')
		
   
    import Managers.Dispatcher as Dispatcher
    from Managers.Messages import Job
    try:
        dispatcher = Dispatcher.Dispatcher()
    except:
        print 'win32 error'
        print traceback.print_exc()
    dispatcher.start()
        
    console(dispatcher)
    
    
    logging.info("Shutting down MatchUpBox")
    dispatcher.close()
    #print threading.enumerate()
    logging.info("Exiting")
    fake_t = threading.Timer(0,None)
    for t in threading.enumerate( ):
        #print t
        if type(t) == type(fake_t):
            t.cancel()
        elif t != threading.current_thread():
            t.join(1)
    sys.exit(1)
