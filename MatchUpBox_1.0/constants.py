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


from os import sep
ipAdresses = {'1' : '192.168.104.80', '2' : '192.168.104.81', '3' : '192.168.104.82', '4' : '192.168.104.83'}
#ipAdresses = {'1' : '193.55.113.90', '2' : '193.55.113.91', '3' : '193.55.113.92', '4' : '193.55.113.93' }

uid_filename = 'conf'+sep+'uid.conf'
nid_filename = 'conf'+sep+'nid.conf'
db_filename = 'dbEP'+sep+'dbEP.db'
routingtable='dbEP'+sep+'routingTbl.dat'
nodes_filename = 'conf'+sep+'nodes.dat'
tis_port="4003"
#tis_ip="192.168.104.90"
tis_ip="193.55.113.98"
#tis_ip="192.168.104.87"

dhtfolder="user_data"
databaseNamePrefix = 'dbData'+sep+'db'
databaseNameExtension = '.db'
default_avatar="avatar.jpg"
bor_file='conf'+sep+'bor'
udp_p="4000"