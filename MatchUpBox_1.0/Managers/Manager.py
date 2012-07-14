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

class Manager(threading.Thread):
    "Manager base class"

    def __init__(self, mName, main_mng):
        self.mName = mName
        super(Manager, self).__init__(name = self.mName)
        self.queue = Queue.Queue()
        self.main_mng = main_mng
        
    def do_work(self, item):
        logging.info("Working on: {0}".format(item))
    
    def add(self,  item):
        self.queue.put(item)
        
    def close(self):
        self.queue.put(None)
        self.queue.join()
        
    def run(self):
        while True:
            item = self.queue.get()
            if item is None:
                break
            self.do_work(item)
            self.queue.task_done()
        self.queue.task_done()
        return
