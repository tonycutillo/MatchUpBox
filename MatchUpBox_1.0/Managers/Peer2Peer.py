#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import hashlib, random, time, datetime, sys, os, binascii
import socket
import logging
import constants as sbconstants
import threading
import time
import traceback
import os
import crypto
import Managers.Manager as Manager
from Messages import P2PMessage, Job, relayMessage

from twisted.internet import defer
from threading import Thread, Timer
import cPickle as pickle
import s2s.routingtable as routingtable
import constants as localC
import s2s.constants as constants
from s2s.contact import Contact
from s2s.datastore import SQLiteDataStore
from twisted.test.test_defer import AlreadyCalledTestCase
from twisted.internet.defer import AlreadyCalledError
numberOfCalls = 0
from Managers.Communication import myPubaddr, ipMap
from Managers.Communication import ipMap

class Peer2PeerMng(Manager.Manager):
    def __init__(self,  mName, main_mng):
        super(Peer2PeerMng, self).__init__(mName, main_mng)
        self.myIP=(myPubaddr[0],myPubaddr[1],myPubaddr[2])
        self.isSSL=myPubaddr[4]
        # read the NodeId from the configuration file
        #conf_filename = "conf"+os.sep+"s2s%s.conf"% sys.argv[1]
        f = open(sbconstants.nid_filename, "r")
        self.id = binascii.unhexlify(f.readline().strip()) # last character read is "\n"!
        f.close()
        f = open(sbconstants.nodes_filename, "r")
        # read the bootstrap contacts from the configuration file 
        self.bootstrapAddresses = []
        for line in f.readlines():
            addr, tcp_port, udp_port, isSSL, nodeid= line.strip().split()
            self.bootstrapAddresses.append([addr,tcp_port,udp_port,isSSL, nodeid])
        f.close()
        
        # REFRESH TIMER
        self.t=Timer(constants.checkRefreshInterval,self._refreshNode)
        
        self.refres_rt=False
        # DB OF SENT MESSAGES
        self._sentMessages = {}
        # self._sentMessages[mex.id] = (contact.id, deferred, timeoutCall)
        
        # DB OF PENDING RESEARCHES [ITERATIVE & RECURSIVE]
        self._researches = {}
        # for the iterative searches: self._researches[mex.target]=[resultContactList, numPending, idAlreadyContacted, Defer]
        # for the recursive searches: self._researches[mex.target]=[resultContactList, numPending, IamTheOriginator[Bool], Defer]
        
        # DB OF STORE ATTEMPTS [ITERATIVE & RECURSIVE]
        self._storeAttempts ={}
        self._unstoreAttempts ={}
        
        db_filename = sbconstants.db_filename
        #andrea not delete the previous db ep but keep the previous one and after the p2p join refresh it  
        self.refresh_data=False
        if not os.path.isfile(db_filename):
            self.refresh_data=True
        self._dataStore = SQLiteDataStore(db_filename)
        
        if self.refresh_data:
            pass
            #self._republishData()
        if not os.path.isfile(sbconstants.routingtable):
            self._routingTable = routingtable.OptimizedTreeRoutingTable(self.id)
        else:
            f=open(sbconstants.routingtable,'rb')
            self._routingTable=pickle.load(f)
            f.close()
            self.refres_rt=True
        logging.info("NodeID: {0}".format(self.id.encode('hex')))               
        print "* NodeID: ", self.id.encode('hex')        
        
    def close(self):
        """ Save the closing state into dbfilename ,
         remove the timer t,
         close the P2P Manager
        """
        logging.info("Shutting down Peer2Peer Manager...")
        f=open(sbconstants.routingtable,'wb')
        pickle.dump(self._routingTable, f,pickle.HIGHEST_PROTOCOL)
        f.close()
        self._persistState()
        self.t.cancel()
        time.sleep(2)
        while not self.queue.empty():
            self.queue.get()
            self.queue.task_done()
        
        super(Peer2PeerMng, self).close()
        print "closing P2P"
        
    def searchIPforMatrioshkaManager(self,list):
        ''' search the ip address in an iterative way  for the list of keys in the list
            @raise ValueError: if the element is not in the list 
            @param list: list of keys that have to be searched on the p2p network
            @return: R_MAT_FIP for each key in the list at the Matrioshka manager.
            @return: nothing if the p2p network is not able to find the keys
        '''
        
        def searchCompleted(result):
            ''' called from a when the iterativeFind finish
                @param list: list of value in iterative search 
                @return: add R_MAT_FIP at the main manager
            '''
            for c in result:
                try:
                    i=list.index(c.id)
#                    ret = (list[i], c.address)
                    ret = (list[i], (c.address,c.tcp_port,c.udp_port),c.isSSL)
#                    print 'searchComp: '+str(ret)
                    job=Job("R_MAT_FIP",ret)
                    self.main_mng.add(job)
                    logging.info("Sent one FIP job to Matrioshka for id: {0}".format(list[i].encode('hex')))
                    list.pop(i)
                except ValueError:
                    pass                 
            
        def searchFailed(result):
            '''
                @return: nothing if the iterativesearch does not return nothing.
            '''
            print "Search IP for Matrioshka failed."
        
        toremove=[]
        for id in list:
            try:
                c = self._routingTable.getContact(id)
                #fakeadd = "127.0.0."+str(c.port)[-1]    # TEMP: to provide fake address for internal Matr. representation 
                #ret = (id, fakeadd)
                ret = (id, (c.address,c.tcp_port,c.udp_port),c.isSSL)
                job=Job("R_MAT_FIP",ret)
                self.main_mng.add(job)
                logging.info("Sent one FIP job to Matrioshka for id: {0}".format(id.encode('hex')))
                toremove.append(id) 
            except ValueError:
                # the contact is not in the routing table, search for it
                df = self.iterativeFind(id)
                df.addCallback(searchCompleted)
                df.addErrback(searchFailed)
        for id in toremove:
            try:
                list.remove(id)
            except:
                pass
    
    #@Ali
    def isLocal(self,ip,myIP):    
        s1=ip.split('.')
        s2=myIP.split('.')
        m1=s1[0]+s1[1]+s1[2]
        m2=s2[0]+s2[1]+s2[2]
        
        if m1==m2:
            return True
        return False
#
#@Ali
    def recieveRelayRequest(self,item):
        if item.type=='RELAYRESPONSE':#@Ali I am the requester
            ipMap[item.data[:3]]=item.data[3]
            print 'Recieved RelayResponse'
        elif item.dest_ip==self.myIP :#@Ali I am the Destination Send the response
            ipMap[item.data[:3]]=item.data[3]
            print 'Recieved RelayRequest'
            res=relayMessage('RELAYRESPONSE', myPubaddr, None)
            self.main_mng.add(Job('S_P2P_RELAYRESPONSE', res, (item.data[3],item.data[1],item.data[2])))
        else:#@Ali I am the relay Node, relay msg to the destination
            print 'Relaying request to destination...'
            res=relayMessage('RELAYREQUEST', item.data, item.dest_ip)
            self.main_mng.add(Job('S_P2P_RELAYREQUEST', res, item.dest_ip))
#
#@Ali    
    def sendRelayRequest(self,data,dest_ip):
        #@Ali find all nodes outside the network
        nodelist=[]
        for i in range(len(self._routingTable._buckets)):
            for contact in self._routingTable._buckets[i]._contacts:
                if not(self.myIP[0]==contact.address):
                    nodelist.append(contact)
            if self._routingTable._replacementCache.has_key(i):
                for c in self._routingTable._replacementCache[i]:
                    if not(self.myIP[0]==c.address):
                        nodelist.append(c)
        if len(nodelist)==0:
            print 'Cannot relay... No contact outside network...'
            return
        
        #@Ali select a random peer to send a relay message
        relay_to=nodelist[random.randrange(0,len(nodelist))]
        item=relayMessage('RELAYREQUEST', data, dest_ip)
        print 'Sending RelayRequest'
        self.main_mng.add(Job('S_P2P_RELAYREQUEST', item, (relay_to.address, relay_to.tcp_port, relay_to.udp_port)))
 #            
    def do_work(self, item):
        '''
            dispatcher for the p2p manager, 
            @param item: item passed from the matrioshka manager
            @type item: if it starts with R_P2P_FIP item.data= list of nodeid
            @type item: if it starts with R_P2P_PER item.data[0]= node id item.data[1]= value to store
            @type item: if it starts with R_P2P_PER item.data[0]= node id to unstore
        '''
        try:
            if item.type.startswith("R_P2P_FIP"):
                timeoutCall = Timer(10,self.searchIPforMatrioshkaManager, [item.data])  # TEMP for testbed: wait untill 
                timeoutCall.start()                                                     # all peers are up            
            elif item.type.startswith("R_P2P_PER"):
                #print "item data"+str(item.data)
                #print 'p2p publish'
                #print item
                self.publishData(item.data[0],item.data[1])
            elif item.type.startswith("R_P2P_UER"):
                #unpublish entry point request
                #item.data[0] is a list[] of key
                #item.data[1] is a Nid to remove
                #(my Nid maybe I am going down)
                self.unpublishData(item.data[0],item.data[1])
            elif item.type.startswith("R_P2P_RELAYREQUEST"):
                self.recieveRelayRequest(item.data)
            elif item.type.startswith("R_P2P_RELAYRESPONSE"):
                self.recieveRelayRequest(item.data)
            else:
                self._handleReceivedDatagram(item.data,item.data.myIP)
        except:
            print 'Error In P2P Do_Work.'
            print traceback.print_exc()
            pass
            

    def _handleReceivedDatagram(self, mex, addrport):
        '''
            _handleReceivedDatagram divide the messages into request or not
                handle the follow messages:
                Request:
                    adding the node in the routing table
                    FINDNODE_REQ
                        send thanks to  _sendDatagram the contacts of closest nodes that it has in it bucket
                    FINDVALUE_REQ
                        send thanks to  _sendDatagram the value at the requester if it is in its local datastore else it search it in the closest nodes
                    STORE_REQ
                        store the value associated at the key and send a STORE_FWD_REQ at the P2P closest nodes
                not request:
                    if it is a message that need a timer it delete the associated timer
                    FINDNODE_RES
                        adding the node in their contact list and removing the outgoing research 
                    FINDVALUE_RES
                        if it is the originator remove the outgoing response
                    UNSTORE_FWD_REQ
                        remove the entry point from the local datastore
                    STORE_FWD_REQ
                        adding the forward key value from message at the dataStore
                    
            @param mex: item.data from matrioshka 
            @type mex:PMessage 
            @param addrport: (port of the node, address of the contact)
        '''
        #print mex
        remoteContact = Contact(mex.senderID, mex.myIP[0],mex.myIP[1],mex.myIP[2],mex.mypkey,mex.isSSL) #esko: safe pkey to contacts		
        if mex.isSSLPacket:#@Ali: if ssl packet, store the contact only for client not the server
            if mex.isClient==True:
                self._routingTable.addContact(remoteContact) # Add/Update the node  in the RT
        else:
            self._routingTable.addContact(remoteContact) # Add/Update the node  in the RT
        
        if mex.isRequest:
            if mex.type=="FINDNODE_REQ":
                logging.debug("Received a FINDNODE_REQ message from {0} - {1}:{2} target: {3}".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                contacts=self._routingTable.findCloseNodes(mex.target,constants.alpha,mex.senderID)
                if mex.isSSLPacket:#@Ali: for ssl client send only contacts with ssl enabaled
                    ssl_con=[]
                    for c in contacts:
                        if c.isSSL==1:
                            ssl_con.append(c)
                    dict={"contactlist":ssl_con}
                else:
                    dict={"contactlist":contacts}
                resmex = P2PMessage("FINDNODE_RES",False, self.id,mex.senderID,mex.target,dict)
                resmex.id=mex.id
                #resmex.myIP=self.myIP
                self._sendDatagram(resmex, remoteContact)
            elif mex.type=="FINDVALUE_REQ":  
                logging.debug("Received a FINDVALUE_REQ message from {0} - {1}:{2} target: {3}".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                if mex.target in self._dataStore:
                    value = self._dataStore[mex.target] # Ok, we have the value locally, so use that
                    logging.debug("I've got the value for key {0}".format(mex.target.encode('hex')))
                    # [TODO: Send this value to the closest node without it]
                    if mex.isSSLPacket:#@Ali: for ssl client send only contacts with ssl enabaled
                        ssl_val=[]
                        for v in value:
                            if v[len(v)-1]==1:
                                ssl_val.append(v)
                        dict={"found_values":ssl_val}
                    else:
                        dict={"found_values":value}
                    resmex = P2PMessage("FINDVALUE_RES",False, self.id,mex.senderID,mex.target,dict)
                    resmex.id=mex.id
                    #resmex.myIP=self.myIP
                    self._sendDatagram(resmex, remoteContact)
                else:
                    if not self._researches.has_key(mex.target): # Loop prevention
                        listClosestContacts = self._routingTable.findCloseNodes(mex.target,constants.alpha,mex.senderID)
                        listClosestContacts.sort(lambda firstContact, secondContact, targetKey=mex.target: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
                        pendingNum=0
                        for ct in listClosestContacts:
                            resmex = P2PMessage("FINDVALUE_REQ",True, self.id,ct.id,mex.target)
                            resmex.id=mex.id
                            #resmex.myIP=self.myIP
                            self._sendDatagram(resmex, ct)
                            pendingNum += 1
                        self._researches[mex.target]=[listClosestContacts,pendingNum,False,remoteContact]
            elif mex.type=="STORE_REQ":
                #print ("Received a STORE_REQ message from {0} - {1}:{2} target: {3}".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                key, value = mex.dict["to_store"][0:2]
                now = int(time.time())
				###########################################################################
				# TONY MOD
				# If same key value exists, overwrite old value
                if key in self._dataStore.keys():
                    Vs=self._dataStore.__getitem__(key)
                    try:
                        Vs.remove(value)
                    except ValueError:
                        pass
                    self._dataStore.__delitem__(key)
                    for Vx in Vs:					
                        self._dataStore.setItem(key, Vx, now, mex.senderID)   # store key-EPT
                
                self._dataStore.setItem(key, value, now, mex.senderID)   # store key-EPT
				############################################################################
				
				
                #self._dataStore.setItem(key, value, now, mex.senderID)   # store key-EPT
                resmex = P2PMessage("STORE_RES",False, self.id,mex.senderID,mex.target)
                resmex.id=mex.id
                #resmex.myIP=self.myIP
                self._sendDatagram(resmex, remoteContact)
                listContacts = self._routingTable.findCloseNodes(mex.target,None,mex.senderID)
                for contact in listContacts:
                    if self._routingTable.distance(contact.id, key) < constants.tollerancezone:
                        #@Ali I dont understand this part
                        #chek if it is work
                        resmex = P2PMessage("STORE_FWD_REQ",False, mex.receiverID,self.id,mex.target,mex.dict)
                        #print ("sending a store forward  from {0} - {1}:{2} target: {3}".format(resmex.senderID.encode('hex'), contact.address, contact.port, resmex.target.encode('hex')))
                        resmex.id=mex.id
                        #Contact(mex.senderID, addrport[0], addrport[1])
                        self._sendDatagram(resmex, Contact(mex.receiverID, contact.address, contact.tcp_port, contact.udp_port, contact.pkey))

            
            elif mex.type=="UNSTORE_REQ":
                key, value = mex.dict["to_unstore"][0:2]
                now = int(time.time())
                ###########################################################################
				# TONY MOD
				# If same key value exists, overwrite old value
                if key in self._dataStore.keys():
                    Vs=self._dataStore.__getitem__(key)
                    try:
                        Vs.remove(value)
                    except ValueError:
                        pass
                    self._dataStore.__delitem__(key)
                    for Vx in Vs:					
                        self._dataStore.setItem(key, Vx, now, mex.senderID)   # store key-EPT
               
				############################################################################
				
				
                #self._dataStore.setItem(key, value, now, mex.senderID)   # store key-EPT
                resmex = P2PMessage("UNSTORE_RES",False, self.id,mex.senderID,mex.target)
                resmex.id=mex.id
                #resmex.myIP=self.myIP
                self._sendDatagram(resmex, remoteContact)
                listContacts = self._routingTable.findCloseNodes(mex.target,None,mex.senderID)
                for contact in listContacts:
                    if self._routingTable.distance(contact.id, key) < constants.tollerancezone:
                        #@Ali I dont understand this part
                        #chek if it is work
                        resmex = P2PMessage("UNSTORE_FWD_REQ",False, mex.receiverID,self.id,mex.target,mex.dict)
                        #print ("sending a store forward  from {0} - {1}:{2} target: {3}".format(resmex.senderID.encode('hex'), contact.address, contact.port, resmex.target.encode('hex')))
                        resmex.id=mex.id
                        #Contact(mex.senderID, addrport[0], addrport[1])
                        self._sendDatagram(resmex, Contact(mex.receiverID, contact.address, contact.tcp_port, contact.udp_port, contact.pkey))
            
            			
        else:
            if self._sentMessages.has_key(mex.id):
                df, timeoutCall = self._sentMessages[mex.id][1:3]
                timeoutCall.cancel()
                try:
                    del self._sentMessages[mex.id]   # NB: all the recursive messages have the same id 
                except:
                    pass
# so, deleting the first that comes, means that the others won't be recognized as
# sentMessages! -> avoid flooding
                
                if mex.type=="FINDNODE_RES":
                    logging.debug("Received a FINDNODE_RES message from {0} - {1}:{2} target: {3}".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                    for c in mex.dict["contactlist"]:
                        self._routingTable.addContact(c)
                    df.callback([mex.target,mex.dict["contactlist"]])
                elif mex.type=="FINDVALUE_RES":
                    logging.debug("Received a FINDVALUE_RES message from {0} - {1}:{2} target: {3}".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                    if self._researches.has_key(mex.target):
                        if not self._researches[mex.target][2]: # I'm NOT the originator of the research
                            logging.debug("Received a FINDVALUE_RES message from {0} - {1}:{2} target: {3} - I am NOT the originator".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                            resmex = P2PMessage("FINDVALUE_RES",False, self.id,remoteContact.id,mex.target, mex.dict)
                            resmex.id = mex.id
                            #resmex.myIP=self.myIP
                            self._sendDatagram(resmex, self._researches[mex.target][3])
                            del self._researches[mex.target]
                        else: # I'm the originator of the research
                            logging.debug("Received a FINDVALUE_RES message from {0} - {1}:{2} target: {3} - I am the originator".format(mex.senderID.encode('hex'), addrport[0],addrport[1], mex.target.encode('hex')))
                            #print mex.dict
                            self._researches[mex.target][3].callback(mex.dict["found_values"])
                            del self._researches[mex.target]
                            # NB: instead of deleting the search, we could decrement the pending number, remove the contact from the list
                            # wait for the other result to arrive and then compare them.
                    ################# check this maybe it is the error 
                elif mex.type=="STORE_RES":
                    logging.debug("Received a STORE_RES message from {0} - {1}:{2}".format(mex.senderID.encode('hex'), addrport[0],addrport[1]))
                    if self._storeAttempts.has_key(mex.target):
                        #self._storeAttempts[mex.target][0].remove(remoteContact)
                        #if len(self._storeAttempts[mex.target][0])<=0:    # TODO this if we want that all the store mex receive 
# a reply in order to declare the store successful
                        self._storeAttempts[mex.target][1].callback("ok")
                        del self._storeAttempts[mex.target]
						
						
                elif mex.type=="UNSTORE_RES":
                    logging.debug("Received an UNSTORE_RES message from {0} - {1}:{2}".format(mex.senderID.encode('hex'), addrport[0],addrport[1]))
                    if self._unstoreAttempts.has_key(mex.target):

                        self._unstoreAttempts[mex.target][1].callback("ok")
                        del self._unstoreAttempts[mex.target]		
						
						
						
						
						
						
                elif mex.type=="UNSTORE_FWD_REQ":
    
                    key, value = mex.dict["to_unstore"][0:2]
		    		###########################################################################
			    	# TONY MOD
                    if key in self._dataStore.keys():
                        Vs=self._dataStore.__getitem__(key)
                        try:
                            Vs.remove(value)
                        except ValueError:
                            pass
                        self._dataStore.__delitem__(key)				
                        for Vx in Vs:					
                            self._dataStore.setItem(key, Vx, now, mex.senderID)   # store key-EPT
				    ############################################################################
                elif mex.type=="STORE_FWD_REQ":
                    #andrea
    
                    key, value = mex.dict["to_store"][0:2]
                    now = int(time.time())

					
					
		    		###########################################################################
			    	# TONY MOD
		    		# If same key value exists, overwrite old value
                    if key in self._dataStore.keys():
                        Vs=self._dataStore.__getitem__(key)
                        try:
                            Vs.remove(value)
                        except ValueError:
                            pass
                        self._dataStore.__delitem__(key)				
                        for Vx in Vs:					
                            self._dataStore.setItem(key, Vx, now, mex.senderID)   # store key-EPT
                    
                    self._dataStore.setItem(key, value, now, mex.senderID)   # store key-EPT
				    ############################################################################
					
					
					
                    #self._dataStore.setItem(key, value, now, mex.senderID) 
                elif mex.type=="REMOVE_ENTRY_POINT_REQ":
                    bucketID=self._routingTable._kbucketIndex(mex.senderID)
                    self._routingTable._buckets[bucketID]._contacts.remove(mex.senderID)
                
    def _sendDatagram(self, mex, contact):
        """
            create a defere for each 
        """
        #logging.debug("Sending message: {0} to node at {1}:{2}".format(mex, contact.address, contact.port))
        df = defer.Deferred()
        if mex.isRequest and mex.type!="R_P2P_UER":
            timeoutCall = None
            try:
                timeoutCall = Timer(constants.rpcTimeout,self._msgTimeout, [mex.id]) # If it is a request message set the timeout for the message sent
                timeoutCall.start()
            except:
                pass
            self._sentMessages[mex.id] = (contact.id, df, timeoutCall)
            
        try:
            pkey = contact.pkey #Esko: pkey for encrytion
        except:
            print "pubkey not found: " + contact.address
        # encapsulate the p2pmex into a sb internal message
        try:
            mex.myIP=self.myIP #@Ali on every p2p msg the routing tables are updated, so with every packet ip information is embedded
            mex.isSSL=self.isSSL
            job = Job("S_P2P_"+mex.type, mex, (contact.address, contact.tcp_port,contact.udp_port), pkey)
            if contact.address == self.myIP[0] and not(ipMap.has_key((contact.address, contact.tcp_port,contact.udp_port))):#@Ali if the contact is in the same network, find the local ip..
                self.sendRelayRequest(myPubaddr,(contact.address, contact.tcp_port,contact.udp_port))
            # add mex to the dispatcher queue 
            self.main_mng.add(job)
        except:
            print "exception raised in _sendDatagram"
            pass
        return df
    def rem_entry_point(self):
        """
        remove all the entry point in the routing table
        and send the message at all contacts into the buckets
               
        @warning: it can flood the network
        @attention: the node is unreachable at the p2p level 
        """
        for i in xrange(len(self._routingTable._buckets)):
            for contact in self._routingTable._buckets[i].getContacts():
                mex = P2PMessage("REMOVE_ENTRY_POINT_REQ",False, self.id,contact.id)
                self._sendDatagram(mex,contact)
                self._routingTable._buckets[i]._contacts.remove(contact.id)

    def joinNetwork(self):                   
        if len(self.bootstrapAddresses)!=0:
            bootstrapContacts = []
            print "* Joining the S2S network, knowing", len(self.bootstrapAddresses), "contacts"
            logging.info("Joining the S2S network, knowing {0} contacts".format(len(self.bootstrapAddresses)))
            #f=open('conf'+os.sep+'bootNID.dat',"r")
            #node = f.readline()
            #f.close()
            #pkeyCore = crypto.loadPublicKey(node+"_N_")
            for address, tcp_port, udp_port, isSSL, nodeid in self.bootstrapAddresses:
                #address, tcp_port,udp_port,isSSL, nodeid = self.bootstrapAddresses
                pkeyCore = crypto.loadPublicKey(nodeid+"_N_")
                contact = Contact(self._generateID(), address, tcp_port,udp_port,pkeyCore, isSSL,0)
                bootstrapContacts.append(contact)
            if self.refres_rt:
                self.refres_rt=False
                self._refreshRoutingTable()
        else:
            print "* Joining the S2S network, knowing no contacts"
            logging.info("Joining the S2S network, knowing no contacts")
            job = Job("R_MAT_MLI", None)
            self.main_mng.add(job)
            '''
             If you do not know anyone try to retraive value from your past routing table
            '''
            if self.refres_rt:
                self.refres_rt=False
                self._refreshRoutingTable()
            self.t.start()
            return
        
        
        
        def joinNetworkFinished(result):
            job = Job("R_MAT_MLI", None)
            self.main_mng.add(job)
            print "* Finished joining the network"
            logging.info("Finished joining the network")
            if self.refresh_data:
                self.refresh_data=False
                now = int(time.time())
                for key in self._dataStore.keys():
                    if now>self._dataStore.lastPublished(key)+constants.dataExpireTimeout:
                        print "Remove old key"
                        self._dataStore.__delitem__(key)
            self.t.start() # starts the refresh timer
        
        def joinNetworkFailed(result):
            print "# Couldn't join the network"
            logging.error("Couldn't join the network")
            self.t.cancel()
        
        df = self.iterativeFind(self.id, bootstrapContacts)
        df.addCallback(joinNetworkFinished)
        df.addErrback(joinNetworkFailed)     
        
    def unpublishDataOLD(self,key):
        ''' unpublish Nid at alpha node
            @param key:  key that have to be find
            @param Nid: Nid that have to be removed
        '''
        logging.info("Unpublishing data")
                    
        def iterativeUnstoreFinished(result):
            def unstoreSucceded(result):
                '''
                If the store is ok, we add a job PEC at the matrioska mng
                '''
                #print "* Value stored correctly."
                #job = Job("R_MAT_PEC",key)
                #self.main_mng.add(job) 
                pass
            def unstoreFailed(result):
                print "# Couldn't remove the value in the found nodes."
                #logging.error("Couldn't store the value in the found nodes.")            
            
            storeDf = defer.Deferred()
            storeDf.addCallback(unstoreSucceded)
            storeDf.addErrback(unstoreFailed)            
            self._unstoreAttempts[key]=[[], storeDf]
            dict={"to_remove":(key)}
            #sorting based on the xor distace
            result.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
            #logging.debug("iterativeStoreFinished called, for the key {0}, now sending STORE_REQ messages".format(key.encode('hex')))
            sent=0
            for contact in result:
                #TODO check this parameter
                if sent< constants.storersNumber:
                    sent+=1
                    mex = P2PMessage("UNSTORE_REQ",True, self.id,contact.id,key,dict)
                    self._unstoreAttempts[key][0].append(contact)
                    self._sendDatagram(mex,contact)
            
            if self._routingTable.distance(key, self.id) < self._routingTable.distance(key, result[-1].id):
                pass #TODO store the value at ourselves in case we are closer than the more far contact from the result list (result.pop())                
 
        def iterativeUnstoreFailed(result):
            #add PEF finished
            #print "# Couldn't find the nodes to unstore the value."
            #logging.error("Couldn't find the nodes to store the value.")
            pass       
         
        
        df = self.iterativeFind(key)
        df.addCallback(iterativeUnstoreFinished)
        df.addErrback(iterativeUnstoreFailed)

    def unpublishData(self, key, value):
        '''
            
            
        '''      
        #print "try to publish data"
        def iterativeUnStoreFinished(result):
            def unstoreSucceded(result):
                pass
            
            def unstoreFailed(result):
                logging.error("Couldn't unstore the value in the found nodes.")            
            unstoreDf = defer.Deferred()
            unstoreDf.addCallback(unstoreSucceded)
            unstoreDf.addErrback(unstoreFailed)            
            self._unstoreAttempts[key]=[[], unstoreDf]
            dict={"to_unstore":(key,value)}
            result.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
            logging.debug("iterativeStoreFinished called, for the key {0}, now sending STORE_REQ messages".format(key.encode('hex')))
            sent=0
            for contact in result:
                if sent< constants.storersNumber:
                    sent+=1
                    mex = P2PMessage("UNSTORE_REQ",True, self.id,contact.id,key,dict)
                    self._unstoreAttempts[key][0].append(contact)
                    self._sendDatagram(mex,contact)
            
            if self._routingTable.distance(key, self.id) < self._routingTable.distance(key, result[-1].id):
                pass #TODO store the value at ourselves in case we are closer than the more far contact from the result list (result.pop())                
        
        def iterativeUnStoreFailed(result):
            logging.error("Couldn't find the nodes to unstore the value.")       
        df = self.iterativeFind(key)
        df.addCallback(iterativeUnStoreFinished)
        df.addErrback(iterativeUnStoreFailed)
	
	
    def publishData(self, key, value):
        '''
            
            
        '''      
        #print "try to publish data"
        def iterativeStoreFinished(result):
            def storeSucceded(result):
                #print "* Value stored correctly."
                job = Job("R_MAT_PEC",key)
                self.main_mng.add(job) 
            
            def storeFailed(result):
                logging.error("Couldn't store the value in the found nodes.")            
            storeDf = defer.Deferred()
            storeDf.addCallback(storeSucceded)
            storeDf.addErrback(storeFailed)            
            self._storeAttempts[key]=[[], storeDf]
            dict={"to_store":(key,value)}
            result.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
            logging.debug("iterativeStoreFinished called, for the key {0}, now sending STORE_REQ messages".format(key.encode('hex')))
            sent=0
            for contact in result:
                if sent< constants.storersNumber:
                    sent+=1
                    mex = P2PMessage("STORE_REQ",True, self.id,contact.id,key,dict)
                    self._storeAttempts[key][0].append(contact)
                    self._sendDatagram(mex,contact)
            
            if self._routingTable.distance(key, self.id) < self._routingTable.distance(key, result[-1].id):
                pass #TODO store the value at ourselves in case we are closer than the more far contact from the result list (result.pop())                
        
        def iterativeStoreFailed(result):
            logging.error("Couldn't find the nodes to store the value.")       
        df = self.iterativeFind(key)
        df.addCallback(iterativeStoreFinished)
        df.addErrback(iterativeStoreFailed)

    def iterativeFind(self,key,startupShortlist=None,myIP=None):
        '''
            @param key: key that have to be search
            @param startupShortlist: start up list of node that are use in the find
            iterativeFind send a FINDNODE_REQ at startupShortlist if it is not None
             or at the alpha nodes that are responsable for the key
            
        '''
        outerDf = defer.Deferred()
        
        def continueResearch(resultArray,myIP=None):
            target = resultArray[0] # target: targetid
            result = resultArray[1] # result: list of Contact            
                     
            if self._researches.has_key(target):                
                self._researches[target][1]-=1 # decrementing number of pending query for this research
                
                newResult=False
                for c in result:
                    if c.id not in self._researches[target][2]: # if the contact is not in already contacted list of the search
                        newResult=True
                        # if we have not found enough contacts
                        if len(self._researches[target][0]) < constants.storersNumber:    
                            # add the contact to the results of the research
                            self._researches[target][0].append(c)
                            self._researches[target][0].sort(lambda firstContact, secondContact, targetKey=target: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
                        elif self._routingTable.distance(c.id, target) < self._routingTable.distance(self._researches[target][0][-1].id, target):
                            # else, if the distance of the contact acquired is less than the distance of the more distant contact in the currentContactList
                            # append the new and remove the more distant of the current results 
                            self._researches[target][0].append(c)
                            self._researches[target][0].sort(lambda firstContact, secondContact, targetKey=target: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
                            self._researches[target][0].pop()
                        
                        # send FINDNODE_REQ
                        if self._researches[target][1] < constants.alpha:
                            self._researches[target][2].append(c.id)
                            self._researches[target][1] += 1
                            mex = P2PMessage("FINDNODE_REQ",True, self.id,c.id,target)
                            mex.myIP=myIP#@Ali
                            df = self._sendDatagram(mex, c)
                            df.addCallback(continueResearch)
                        
                if not newResult and self._researches[target][1]==0: # the search has not given new result and there are no searches pending
                    # ---- SEARCH FINISHED ----
                    logging.debug("Search iterations for target {0} finished".format(target.encode('hex')))
                    self._researches[key][3].callback(self._researches[target][0])
                    del self._researches[target]        
            else:
                logging.error("Received a FINDNODE_RES mex for a research not active, target: {0}".format(target.encode('hex'))) # shouldn't happen
                                      
        # ---- SEARCH STARTED ----               
        if startupShortlist == None:
            listClosestContacts = self._routingTable.findCloseNodes(key,constants.alpha)
        else:
            listClosestContacts = startupShortlist
            
        listClosestContacts.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
        self._researches[key]=[listClosestContacts,0,[],outerDf] 
        
    
        for ct in listClosestContacts:
            self._researches[key][1]+=1
            self._researches[key][2].append(ct.id)
            mex = P2PMessage("FINDNODE_REQ",True, self.id,ct.id,key)
            mex.myIP=myIP#@Ali
            df = self._sendDatagram(mex, ct)
            df.addCallback(continueResearch)
        
        return outerDf 


    def recursiveFind(self, word):
        outerDf = defer.Deferred()
        h = hashlib.sha1()
        h.update(word)
        key = h.digest()
        # NB: Does not search in the local store (has to be done somewhere else!)  
            #this is not optimixed but this follow the procololl I send a request at my self
        listClosestContacts = self._routingTable.findCloseNodes(key,constants.alpha)
        listClosestContacts.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
        self._researches[key]=[listClosestContacts,len(listClosestContacts),True,outerDf]  # Bool value: I'm the originator

        for ct in listClosestContacts:
            mex = P2PMessage("FINDVALUE_REQ",True, self.id,ct.id,key)
            self._sendDatagram(mex, ct)

        return outerDf  
    
    def recursiveFind2(self, word):
        outerDf = defer.Deferred()
        key = word
        # NB: Does not search in the local store (has to be done somewhere else!)  
        
        listClosestContacts = self._routingTable.findCloseNodes(key,constants.alpha)
        listClosestContacts.sort(lambda firstContact, secondContact, targetKey=key: cmp(self._routingTable.distance(firstContact.id, targetKey), self._routingTable.distance(secondContact.id, targetKey)))
        self._researches[key]=[listClosestContacts,len(listClosestContacts),True,outerDf]  # Bool value: I'm the originator

        for ct in listClosestContacts:
            mex = P2PMessage("FINDVALUE_REQ",True, self.id,ct.id,key)
            self._sendDatagram(mex, ct)

        return outerDf
    
    def _generateID(self):
        hash = hashlib.sha1()
        hash.update(str(random.getrandbits(255)))
        return hash.digest()    
    
    def _msgTimeout(self, msgid):
        try:
            if self._sentMessages.has_key(msgid):
                try:
                    del self._sentMessages[msgid]
                except:
                    pass
                recid = msgid.split("-")[1].decode('hex')
                logging.warning("msgTimeout for {0}".format(msgid))
                
                if msgid.startswith("FINDNODE"):
                    #print "# msgTimeout for ", msgid,": removing the contact."
                    try:
                        self._routingTable.removeContact(recid) # remove the contact
                    except:
                        pass
                    target=msgid.split("-")[2].decode('hex')
                    if self._researches.has_key(target):
                        self._researches[target][1]-=1
                        fakecontact = Contact(recid,"127.0.0.1",5000,4000,False)
                        if fakecontact in self._researches[target][0]:         # if the non-responding contact was in the result of the search
                            try:
                                self._researches[target][0].remove(fakecontact)    # remove it
                            except:
                                pass
                        if self._researches[target][1]<=0:                      # if pendingNum=0
                            if self._researches[target][2]<=constants.alpha:    # None of the alpha contacts contacted at the first round answered:
                                                                                # ---- SEARCH FAILED ----
                                self._researches[target][3].errback(Exception)
                            else:
                                # ---- SEARCH FINISHED ----
                                #print "*** Search iterations for target ",target.encode('hex')," finished"
                                self._researches[target][3].callback(self._researches[target][0])
                            if target in self._researches.keys():
                                try:
                                    del self._researches[target]
                                except:
                                    pass
                            
                elif msgid.startswith("FINDVALUE"):
                    # NB: if a node involved in a recursive search does not reply
                    # doesn't mean that it is dead: maybe in the successive steps 
                    # of the recursion something went wrong, not depending on it.
                    # so: don't remove the contact from RT
                    #self._routingTable.removeContact(recid)
                    target=msgid.split("-")[2].decode('hex')
                    if self._researches.has_key(target):
                        self._researches[target][1]-=1
                        if self._researches[target][1]<=0 and self._researches[target][2]:  # decrement the pending number, and call the errback if pendingNum=0 and "I am the originator"
                            self._researches[target][3].errback(Exception)                  # ---- SEARCH FAILED ----
                            if target in self._researches.keys():
                                try:
                                    del self._researches[target]
                                except:
                                    pass
                            
                elif msgid.startswith("STORE"):
                    try:
                        self._routingTable.removeContact(recid) # remove the contact
                    except:
                        pass
                    target=msgid.split("-")[2].decode('hex')
                    if self._storeAttempts.has_key(target):
                        try:
                            if self._storeAttempts[target][0].count(self._routingTable.getContact(recid)) != 0:
                                self._storeAttempts[target][0].remove(self._routingTable.getContact(recid))
                        except:
                            pass
                        if len(self._storeAttempts[target][0])<=0:
                            self._storeAttempts[target][1].errback(Exception)    # ----- STORED FAILED -----
                            if target in self._storeAttempts.keys():
                                try:
                                    del self._storeAttempts[target]                 # if any of the stored mex sent receive no reply, the store fail
                                except:
                                    pass
    
        #============================================================================== DEBUG
        except AlreadyCalledError:
            pass
        
        
    def _printContacts(self):
        print '\n\nNODE CONTACTS\n=================================='
        for i in range(len(self._routingTable._buckets)):
            print "BUCKET",i,": from %E to %E, last accessed: %s" % (self._routingTable._buckets[i].rangeMin,self._routingTable._buckets[i].rangeMax, datetime.datetime.fromtimestamp(self._routingTable._buckets[i].lastAccessed).strftime("%Y-%m-%d %H:%M:%S"))
            for contact in self._routingTable._buckets[i]._contacts:
                print contact
            if self._routingTable._replacementCache.has_key(i):
                print "Replacement cache:"
                for c in self._routingTable._replacementCache[i]:
                    print c
            print
        print '=================================='
        
    def _printStoredData(self):
        print '\n\nSTORED DATA\n=================================='
        for key in self._dataStore.keys():
            print self._dataStore[key]
            print
        print '=================================='
        
    def _watch(self):
        print "\n\nONGOING RESEARCHES\n==============================="
        for res in self._researches.keys():
            print res.encode('hex'), "pendingNum:", self._researches[res][1]
            for c in self._researches[res][0]:
                print "    ",c
            print
        print '=================================='
        print "\n\nSENT MESSAGES\n==============================="
        for mexid in self._sentMessages.keys():
            print mexid
        print '=================================='
        print "\n\nSTORE ATTEMPTS\n==============================="
        for key in self._storeAttempts.keys():
            print key.encode('hex')
            for i in self._storeAttempts[key][0]:
                print i
            print
        print '=================================='


    #========================================================================= REFRESH LOGIC

    def _refreshNode(self):
        """ Periodically called to perform k-bucket refreshes and data
        replication/republishing as necessary """
        logging.debug("_refreshNode called")
        df = self._refreshRoutingTable()
        df.addCallback(self._republishData)
        df.addCallback(self._scheduleNextNodeRefresh)

    def _refreshRoutingTable(self):
        nodeIDs = self._routingTable.getRefreshList(0, False)
        #print "    * _________Got",len(nodeIDs),"ids to look for"
        outerDf = defer.Deferred()
        def searchForNextNodeID(dfResult=None):
            if len(nodeIDs) > 0:
                searchID = nodeIDs.pop()
                df = self.iterativeFind(searchID)
                df.addCallback(searchForNextNodeID)
                df.addErrback(searchForNextNodeID)
            else:
                # If this is reached, we have finished refreshing the routing table
                outerDf.callback(None)
        # Start the refreshing cycle
        searchForNextNodeID()
        return outerDf
    
    def _republishData(self, *args):
        logging.debug("_republishData called")
        expiredKeys = []
        for key in self._dataStore:
            if key == 'nodeState':  # Filter internal variables stored in the datastore
                continue
            now = int(time.time())
            #age = now - self._dataStore.lastPublished(key)
            #if age >= constants.dataExpireTimeout:
            #    self.publishData(key, self._dataStore[key])
    
    def _scheduleNextNodeRefresh(self, *args):
        logging.debug("_scheduleNextNodeRefresh called")
        self.t=Timer(constants.checkRefreshInterval,self._refreshNode)
        self.t.start()
        
    #========================================================================= PERSISTENCE LOGIC                
        
    def _persistState(self):
        logging.debug("_persistState called")  
        contacts = self._routingTable.findCloseNodes(self.id, constants.k)
        contactTriples = []
        for contact in contacts:
            contactTriples.append( (contact.id, contact.address, contact.udp_port) )
        state = {'closestNodes': contactTriples}
        now = int(time.time())
		###########################################################################
		# TONY MOD
		# If same key value exists, overwrite old value
        if 'nodeState' in self._dataStore.keys():
            Vs=self._dataStore.__getitem__('nodeState')
            try:
                Vs.remove(state)
            except ValueError:
                pass
            self._dataStore.__delitem__('nodeState')
            for Vx in Vs:					
                self._dataStore.setItem('nodeState', Vx, now, mex.senderID)   # store key-EPT			
        self._dataStore.setItem('nodeState', state, now, self.id)   # store key-EPT
		############################################################################
		
        #self._dataStore.setItem('nodeState', state, now, self.id)