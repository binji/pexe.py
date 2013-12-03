#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import ctypes
import struct


def IsPowerOfTwo(n):
  return n & (n - 1) == 0


class Memory(object):
  def __init__(self, num_bytes):
    self.data = ctypes.create_string_buffer(num_bytes)

  def ReadU8(self, offset):
    return struct.unpack_from('<B', self.data, offset)[0]

  def ReadU16(self, offset):
    return struct.unpack_from('<H', self.data, offset)[0]

  def ReadU32(self, offset):
    return struct.unpack_from('<L', self.data, offset)[0]

  def ReadU64(self, offset):
    return struct.unpack_from('<Q', self.data, offset)[0]

  def ReadF32(self, offset):
    return struct.unpack_from('<f', self.data, offset)[0]

  def ReadF64(self, offset):
    return struct.unpack_from('<d', self.data, offset)[0]

  def WriteU8(self, offset, value):
    return struct.pack_into('<B', self.data, offset, value)

  def WriteU16(self, offset, value):
    return struct.pack_into('<H', self.data, offset, value)

  def WriteU32(self, offset, value):
    return struct.pack_into('<L', self.data, offset, value)

  def WriteU64(self, offset, value):
    return struct.pack_into('<Q', self.data, offset, value)

  def WriteF32(self, offset, value):
    return struct.pack_into('<f', self.data, offset, value)

  def WriteF64(self, offset, value):
    return struct.pack_into('<d', self.data, offset, value)

  def __repr__(self):
    return str(map(ord, self.data))


class MemoryWriter(object):
  def __init__(self, memory):
    self.offset = 0
    self.memory = memory

  def WriteU8(self, value):
    self.memory.WriteU8(self.offset, value)
    self.offset += 1

  def WriteU16(self, value):
    self.memory.WriteU16(self.offset, value)
    self.offset += 2

  def WriteU32(self, value):
    self.memory.WriteU32(self.offset, value)
    self.offset += 4

  def WriteU64(self, value):
    self.memory.WriteU64(self.offset, value)
    self.offset += 8

  def WriteF32(self, value):
    self.memory.WriteF32(self.offset, value)
    self.offset += 4

  def WriteF64(self, value):
    self.memory.WriteF64(self.offset, value)
    self.offset += 8

  def Skip(self, num_bytes):
    self.offset += num_bytes

  def Align(self, to):
    assert IsPowerOfTwo(to)
    self.offset = (self.offset + (to - 1)) & ~(to - 1)


class NullMemoryWriter(object):
  def __init__(self):
    self.offset = 0

  def WriteU8(self, _):
    self.offset += 1

  def WriteU16(self, _):
    self.offset += 2

  def WriteU32(self, _):
    self.offset += 4

  def WriteU64(self, _):
    self.offset += 8

  def WriteF32(self, _):
    self.offset += 4

  def WriteF64(self, _):
    self.offset += 8

  def Skip(self, num_bytes):
    self.offset += num_bytes

  def Align(self, to):
    assert IsPowerOfTwo(to)
    self.offset = (self.offset + (to - 1)) & ~(to - 1)
