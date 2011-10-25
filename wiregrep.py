#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       wire_reader.py
#       
#       Copyright 2011 Philippe Langlois <phil@p1sec.com>
#       
#       Closed source, proprietary and confidential code.
#       
#       

import pyshark
import sys
import binascii

class wiregrep():
  def __init__(self, pfile = None, wire_filter = 'ip.version eq 4 and sctp.chunk_type == 2'):
    self.pcap = 0
    self.pfile = pfile
    self.wire_filter = wire_filter
    if pfile != None:
      self.add(pfile)

  def add(self, pfile): 
    #      wire_filter = 'ip.version eq 4 and sctp.chunk_type == 2', 
    #      collect_fields = ['frame.number', 'sctp.parameter_state_cookie']
    #      ):
    self.pfile = pfile
    #self.pcap = pyshark.read(pfile, ['frame.number', 'frame'], self.wire_filter)
    self.pcap = pyshark.read(pfile, ['frame.number'], self.wire_filter)

  def count(self):
    return(len(self.pcap))


def main(argv):
  if len(argv) < 3:
    print ("Usage: %s 'filter' files" % argv[0])
    sys.exit(-1)
  wire_filter = argv[1]
  files = argv[2:]
  for mfile in files:
    wg = wiregrep(mfile, wire_filter)
    if wg.count() > 0:
      print mfile
    else:
      del(wg)

if __name__ == '__main__':
	main(sys.argv)

