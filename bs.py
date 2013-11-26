#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

d = open(sys.argv[1]).read()
d = ''.join((('0' * 8) + bin(ord(x))[2:])[::-1][:8] for x in d)
o = 0
while d:
  print '%06x' % o, '|',
  x = d[:32]
  while x:
    y = x[:8]
    print y,
    x = x[8:]
  print x
  d = d[32:]
  o += 4
