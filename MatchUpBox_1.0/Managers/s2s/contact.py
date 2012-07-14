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

class Contact(object):
    def __init__(self, id, ipAddress, tcpPort,udpPort, pkey, isssl=None,firstComm=0):
        self.id = id
        self.address = ipAddress
        self.udp_port = udpPort
        self.tcp_port=tcpPort
        self.pkey = pkey #esko: public for p2p encryption
        self.isSSL=isssl
        self.commTime = firstComm
        
        
    def __eq__(self, other):
        if isinstance(other, Contact):
            return self.id == other.id
        elif isinstance(other, str):
            return self.id == other
        else:
            return False
    
    def __ne__(self, other):
        if isinstance(other, Contact):
            return self.id != other.id
        elif isinstance(other, str):
            return self.id != other
        else:
            return True
        
    def __str__(self):
        return '<IP@: %s, TCPPort: %s, UDPport: %s, ID: %s, IsSSL: %s, pkey: %s>' % (self.address, self.tcp_port,self.udp_port, self.id.encode('hex'),str(self.isSSL), self.pkey)