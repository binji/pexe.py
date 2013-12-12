#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import ctypes
import struct

# Type enum
U8 = 1
U16 = 2
U32 = 3
U64 = 4
F32 = 5
F64 = 6


def IsPowerOfTwo(n):
  return n & (n - 1) == 0


def Align(offset, alignment):
  assert IsPowerOfTwo(alignment)
  return (offset + (alignment - 1)) & ~(alignment - 1)


def ReadCString(memory, offset):
  result = []
  while True:
    c = memory.ReadU8(offset)
    if c == 0:
      break
    result.append(chr(c))
    offset += 1
  return ''.join(result)


class Memory(object):
  def __init__(self, num_bytes):
    self.data = ctypes.create_string_buffer(num_bytes)
    self.num_bytes = num_bytes

  def Resize(self, new_num_bytes):
    new_data = ctypes.create_string_buffer(new_num_bytes)
    ctypes.memmove(new_data, self.data, min(self.num_bytes, new_num_bytes))
    self.data = new_data
    self.num_bytes = new_num_bytes

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

  ReadFuncs = {
      U8: ReadU8,
      U16: ReadU16,
      U32: ReadU32,
      U64: ReadU64,
      F32: ReadF32,
      F64: ReadF64
  }

  def Read(self, typ, offset):
    return Memory.ReadFuncs[typ](self, offset)

  def WriteU8(self, offset, value):
    struct.pack_into('<B', self.data, offset, value)

  def WriteU16(self, offset, value):
    struct.pack_into('<H', self.data, offset, value)

  def WriteU32(self, offset, value):
    struct.pack_into('<L', self.data, offset, value)

  def WriteU64(self, offset, value):
    struct.pack_into('<Q', self.data, offset, value)

  def WriteF32(self, offset, value):
    struct.pack_into('<f', self.data, offset, value)

  def WriteF64(self, offset, value):
    struct.pack_into('<d', self.data, offset, value)

  WriteFuncs = {
      U8: WriteU8,
      U16: WriteU16,
      U32: WriteU32,
      U64: WriteU64,
      F32: WriteF32,
      F64: WriteF64
  }

  def Write(self, typ, offset, value):
    Memory.WriteFuncs[typ](self, offset, value)

  def __repr__(self):
    return str(map(ord, self.data))


class NullMemory(object):
  def _Read(self, offset):
    return 0

  def _Write(self, offset, value):
    pass

  def Read(self, typ, offset):
    return 0

  def Write(self, typ, offset, value):
    pass

  ReadU8 = _Read
  ReadU16 = _Read
  ReadU32 = _Read
  ReadU64 = _Read
  ReadF32 = _Read
  ReadF64 = _Read
  WriteU8 = _Write
  WriteU16 = _Write
  WriteU32 = _Write
  WriteU64 = _Write
  WriteF32 = _Write
  WriteF64 = _Write


class MemoryWriter(object):
  def __init__(self, memory, offset=0):
    self.offset = offset
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

  def Align(self, alignment):
    self.offset = Align(self.offset, alignment)
