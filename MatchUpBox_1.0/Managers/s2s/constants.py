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

######### KADEMLIA CONSTANTS ###########
key_size=160
def compute_teshold(alpha,key_size):
    value=1
    treshold=0
    while value<alpha:
         treshold+=pow(2,key_size-value)
         value+=1
    return long(treshold)

#: Small number Representing the degree of parallelism in network calls
alpha = 3 #3

#: Number of degree of parallelism in the second network calls
beta=2

tollerancezone=compute_teshold(alpha,key_size)
#: Maximum number of contacts stored in a bucket; this should be an even number
k = 2 #8

#: Timeout for network operations (in seconds)
rpcTimeout = 10

# Delay between iterations of iterative node lookups (for loose parallelism)  (in seconds)
#iterativeLookupDelay = rpcTimeout / 2

#: If a k-bucket has not been used for this amount of time, refresh it (in seconds)
refreshTimeout = 3600 # 1 hour
#: The interval at which nodes replicate (republish/refresh) data they are holding
#replicateInterval = refreshTimeout
# The time it takes for data to expire in the network; the original publisher of the data
# will also republish the data at this time if it is still valid
dataExpireTimeout = 10 # 86400 # 24 hours

######## IMPLEMENTATION-SPECIFIC CONSTANTS ###########

#: The interval in which the node should check whether any buckets need refreshing,
#: or whether any data needs to be republished (in seconds)
checkRefreshInterval = 720 # 10 minutes

#: Max size of a single UDP datagram, in bytes. If a message is larger than this, it will
#: be spread accross several UDP packets.
#udpDatagramMaxSize = 8192 # 8 KB

# Number of nodes that have to store the key-value pair 
storersNumber = 2
