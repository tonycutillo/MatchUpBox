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


import threading
import Queue
import Managers.Communication as Communication
import Managers.User as User
import Managers.Matryoshka as Matryoshka
import Managers.Peer2Peer as Peer2Peer
import logging 


class Dispatcher(threading.Thread):
    "Dispatcher class"

    def __init__(self):
        self.l = threading.Lock()
        super(Dispatcher, self).__init__(name = "Dispatcher")
        self.queue = Queue.Queue()

        self.com = Communication.CommunicationMng("Communication Mng", self)
        self.com.start() # start Communication Manager

        self.p2p = Peer2Peer.Peer2PeerMng("Peer2Peer Mng", self)
        self.p2p.start() # start Peer2Peer Manager
        self.p2p.joinNetwork()
        
        self.usr = User.UserMng("User Mng", self)
        self.usr.start() # start User Manager  
        
        #zengin: in order to fill database Matryoshka needs a reference to usr.
        self.mat = Matryoshka.MatryoshkaMng("Matryoshka Mng", self, self.usr)
        self.mat.start() # start Matryoshka Manager
             
        



    def do_work(self, item):
        try:
            if item.type.startswith("S_P2P"):
                #logging.info("Sending {0.type} to Comunication manager".format(item))
                self.com.add(item)
            elif item.type.startswith("R_P2P"):
                #logging.info("Sending {0.type} to P2P manager".format(item))
                self.p2p.add(item)
                
            elif item.type.startswith("R_USR"):
                #logging.info("Sending {0} to User manager".format(item))
                self.usr.add(item)
    
            
            elif item.type.startswith("S_MAT"):
                logging.info("Sending {0.type} to Comunication manager".format(item))
                self.com.add(item)
            elif item.type.startswith("R_MAT"):
                logging.info("Sending {0.type} to Matryoshka manager".format(item))
                self.mat.add(item)
            else:
                logging.info("Message {0.type} unknown".format(item))
        except:
            print 'Error in Dispatcher Do_Work.'
            pass
    
    def add(self,  item):
        self.l.acquire()
        self.queue.put(item)
        self.l.release()
    def close(self):
#@Ali        Enclosing all in try catch successfully close the MatchUpBox, even though if it encounter in particular manager, still it will manage to close rest of the threads. If otherwise one manager fails, all other are skiped.

        print "usr"
        try:
            self.usr.close()
        except:
            pass
        print "mat"
        try:
            self.mat.close()
        except:
            pass
        print "p2p"
        try:
            self.p2p.close()
        except:
            pass
        print "com"
        try:
            self.com.close()
        except:
            pass
        print "queue"
        try:
            self.queue.put(None)
            self.queue.join()
        except:
            pass
        
    def run(self):
        while True:
            item = self.queue.get()
            if item is None:
                break
            self.do_work(item)
            self.queue.task_done()
        self.queue.task_done()
        return
