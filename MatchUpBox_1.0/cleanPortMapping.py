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

#to remove all mapping, comment the code below and run this alone.
def deleteMapping():
    start_tcp=5000
    start_udp=4000
    end_tcp=5050
    end_udp=4050
    import UPnPInterface
    upnp=UPnPInterface.UPnPInterface();
    print "Removing TCP mappings"
    while True:
        try:
            upnp.removePortMaping(start_tcp, 'TCP')
        except:
            break
        if start_tcp==end_tcp:
            break
        start_tcp=start_tcp+1
    print "Removing UDP mappings"
    while True:
        try:
            upnp.removePortMaping(start_udp,'UDP')
        except:
            break
        if start_udp==end_udp:
            break
        start_udp=start_udp+1

try:
    print "start"
    deleteMapping()
except:
    print "error"