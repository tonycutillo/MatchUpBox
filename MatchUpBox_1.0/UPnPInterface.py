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



'''
Created on May 31, 2011

@author: ali
'''

import miniupnpc

class UPnPInterface:
    '''
    It provides an interface to excess UPnP services to enable p2p communication behind NAT
    In order to execute this interface install Ming32 (http://www.mingw.org/) and integrate MiniUpnp (http://miniupnp.free.fr/)
    '''


    def __init__(self):
        '''
        Constructor: Initializes the UPnP Object
        '''
        try:
            # create the UPnP object
            self.upnpObj = miniupnpc.UPnP()
            self.upnpObj.discoverdelay = 200;
            self.ndevices = self.upnpObj.discover()            
            
            # select an igd
            self.upnpObj.selectigd()
            self.privateIP=self.upnpObj.lanaddr
            self.publicIP=self.upnpObj.externalipaddress()
            self.portForwarded=0;
            
        except Exception, e:
            print 'Exception :', e;
            raise e;
    def reset(self):
        try:
            # create the UPnP object
            self.upnpObj = miniupnpc.UPnP()
            self.upnpObj.discoverdelay = 200;
            self.ndevices = self.upnpObj.discover()            
            
            # select an igd
            self.upnpObj.selectigd()
            self.privateIP=self.upnpObj.lanaddr
            self.publicIP=self.upnpObj.externalipaddress()
            self.portForwarded=0;
            
        except Exception, e:
            print 'Exception :', e
        
    def getPriviteIP(self):
        return self.privateIP;
    
    def getPublicIP(self):
        return self.publicIP;
    
    def getPortForwarded(self):
        return self.portForwarded;
    
    def getIGDinfo(self):
        # display information about the IGD and the internet connection
        print 'local ip address :', self.privateIP
        print 'external ip address :', self.publicIP
        print self.upnpObj.statusinfo(), self.upnpObj.connectiontype()
        
    def forwardPortTo(self,lan_port,protocol):
        #lan_port = local listining socket port     protocol = 'TCP' 'UDP'
        #This function tries to find a next avalible port on router and map the local ip with the public ip
        ext_port=lan_port
        r = self.upnpObj.getspecificportmapping(ext_port, protocol)
        while r != None and ext_port < 65536:
            print 'unable to forward port ', ext_port
            ext_port = ext_port + 1
            r = self.upnpObj.getspecificportmapping(ext_port, protocol)
        lan_port=ext_port
        print 'trying to redirect %s port %u %s => %s port %u %s' % (self.publicIP, ext_port, protocol,self.privateIP, lan_port,protocol)
    
        b = self.upnpObj.addportmapping(ext_port, protocol, self.privateIP, lan_port,
                            'MatchUpBox %u' % ext_port, '')
        if b:
            print 'Success. Now waiting for incoming traffic on %s:%u' % (self.publicIP ,ext_port)
            self.portForwarded=ext_port;            
        else:
            print 'Failed'
        return self.portForwarded;
    
    def removePortMaping(self,ext_port,protocol):
        b = self.upnpObj.deleteportmapping(ext_port, protocol)
        if b:
            print 'Successfully deleted port mapping on port ', ext_port 
        else:
            print 'Failed to remove port mapping on port ', ext_port
    
    
    
        
        
        
        
        
        
        
        
        
        
        
        
        
        