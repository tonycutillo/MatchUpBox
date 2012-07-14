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

import time
import crypto
import constants


        

class Job(object):
    def __init__(self, type, data, addr=None, pkey=None):
        self.type = type
        self.data = data
        self.addr = addr
        self.alt_addr=()
        self.pkey = pkey #delivering pkey for comm mgt. 
        
    def __str__(self):
        if self.addr != None:
            return ("[type: {0.type} - to/from_ip: {0.addr}]".format(self))
        else:
            return ("[type: {0.type}]".format(self))

"""
P2P Message types:

PING_REQ - PING_RES
FINDNODE_REQ - FINDNODE_RES
FINDVALUE_REQ - FINDVALUE_RES
STORE_REQ - STORE_RES
"""
class P2PMessage():
    
    def __init__(self, type, isReq, sendID, recID, target=None, dict=None,myIP=None,isSSL=None, mypkey=None):
        f = open(constants.nid_filename, 'r')
        nodeid = f.readline()
        f.close()
        mypkey = crypto.loadPublicKey(nodeid+"_N_")
        self.type = type
        self.isRequest=isReq
        self.senderID = sendID
        self.receiverID = recID
        
        self.target = target
        self.dict = dict
        self.alt_addr=()
        self.myIP=myIP
        self.isSSL=isSSL
        self.mypkey = mypkey #esko: the public key of sender is added to every p2p message 
        
        
        if self.target != None:
            self.id=self.type+"-"+self.receiverID.encode('hex')+"-"+self.target.encode('hex')
        else:
            self.id=self.type+"-"+self.receiverID.encode('hex')
        #self.id=int(time.time())
        
    def __str__(self):
        if self.target != None:
            return '[%s Mex; From: %s; To: %s; Target: %s; pkey: %s]' % (self.type, self.senderID.encode('hex'), self.receiverID.encode('hex'), self.target.encode('hex'), self.mypkey)
        else:
            return '[%s Mex; From: %s; To: %s]' % (self.type, self.senderID.encode('hex'), self.receiverID.encode('hex'))

class relayMessage():
    def __init__(self, type, data, dest_ip, pkey=None):
        self.type=type#Request/Response
        self.dest_ip=dest_ip
        self.data=data
        self.pkey=pkey
    
class MatMessage():
    def __init__(self, fromNid, type, data, to_ip, pkey):
        self.fromNid = fromNid
        self.type = type
        self.data = data
        self.to_ip = to_ip
        self.pkey = pkey
        
    def __str__(self):
        return ("[fromNid: {0.fromNid} - type: {0.type} - data: {0.data} - {0.to_ip}]".format(self))
        
