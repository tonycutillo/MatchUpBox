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

import threading

def debug(f):
    def tmp(*args, **kwargs):
        if not debug.local:
            debug.local = threading.local()
            debug.local.indent=0
            debug.local.tid = threading.current_thread().name
        debug.local.indent+=1
        
        tmp = ", ".join([str(i) for i in args]) + ", ".join("%s=%s" %(k,w) for k,w in kwargs.items())
        print "%s[%s] Calling %s(%s)... " % ("\t"*(debug.local.indent-1), debug.local.tid, f.__name__, tmp)
        t = f.__call__(*args, **kwargs)
        print "%s[%s] Return = %s" % ("\t"*(debug.local.indent-1), debug.local.tid, t)
        debug.local.indent-=1
        return t
    return tmp
debug.local = 0

if __name__ == '__main__':
    @debug
    def potenza(f):
        return f*f * second_level(f)
        
        
    @debug
    def second_level(*args):
        return 10+third_level(args)
        
    
    @debug
    def third_level(*args):
        return reduce(lambda x,y:x+y, args)[0]



    tmp = potenza(3)
    print "tmp = %s" % tmp

