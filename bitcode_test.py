#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import bitcode

def BS(a):
  s = ''.join([chr(x) for x in a])
  return bitcode.BitStream(s)

class BitStreamTest(unittest.TestCase):
  def testRead(self):
    bs = BS([0b10111111, 0b00001111])
    self.assertEqual(0, bs.TellBit())
    self.assertEqual(0b11111, bs.Read(5))
    self.assertEqual(5, bs.TellBit())
    self.assertEqual(0b11101, bs.Read(5))
    self.assertEqual(10, bs.TellBit())
    self.assertEqual(0b00011, bs.Read(5))
    self.assertEqual(15, bs.TellBit())
    self.assertEqual(0b0, bs.Read(1))
    self.assertEqual(16, bs.TellBit())
    self.assertTrue(bs.AtEnd())

  def testMultiByteRead(self):
    bs = BS([0x12, 0x34, 0x56])
    self.assertEqual(0x563412, bs.Read(24))
    self.assertEqual(24, bs.TellBit())
    self.assertTrue(bs.AtEnd())

  def testMultiByteUnalignedRead(self):
    bs = BS([0xab, 0xcd, 0xef, 0x11])
    self.assertEqual(0, bs.TellBit())
    self.assertEqual(0xb, bs.Read(4))
    self.assertEqual(4, bs.TellBit())
    self.assertEqual(0xfcda, bs.Read(16))
    self.assertEqual(20, bs.TellBit())
    self.assertEqual(0x11e, bs.Read(12))
    self.assertEqual(32, bs.TellBit())
    self.assertTrue(bs.AtEnd())

  def testReadVbr(self):
    bs = BS([0b01100100, 0b10010110, 0b00011])
    # 001 | 100 | 100
    #  01    00    00
    # 10000
    self.assertEqual(0b10000, bs.ReadVbr(3))
    self.assertEqual(9, bs.TellBit())
    # 0001 | 1100 | 1011
    #  001    100    011
    # 1100011
    self.assertEqual(0b1100011, bs.ReadVbr(4))
    self.assertEqual(21, bs.TellBit())
    self.assertFalse(bs.AtEnd())

  def testSeekBit(self):
    bs = BS([0b11100111, 0b11001100, 0b11100000])
    bs.SeekBit(10)
    self.assertEqual(0b00110011, bs.Read(10))
    bs.SeekBit(9)
    self.assertEqual(0b001100110, bs.Read(11))
    bs.SeekBit(0)
    self.assertEqual(0b0111, bs.Read(4))
    self.assertFalse(bs.AtEnd())

  def testAlign32(self):
    bs = BS([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde])
    self.assertEqual(0x412, bs.Read(12))
    bs.Align32()
    self.assertEqual(32, bs.TellBit())
    bs.Align32()
    self.assertEqual(32, bs.TellBit())
    self.assertEqual(0xbc9a, bs.Read(16))
    self.assertFalse(bs.AtEnd())

if __name__ == '__main__':
  unittest.main()
