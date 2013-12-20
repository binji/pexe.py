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

TYPE_TO_PACK_FMT = {
  U8: '<B',
  U16: '<H',
  U32: '<L',
  U64: '<Q',
  F32: '<f',
  F64: '<d',
}

SIZEOF_TYPE = {
  U8: 1,
  U16: 2,
  U32: 4,
  U64: 8,
  F32: 4,
  F64: 8,
}


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
  def Read(self, typ, offset):
    raise NotImplementedError()

  def Write(self, typ, offset, value):
    raise NotImplementedError()

  def ReadU8(self, offset):  return self.Read(U8, offset)
  def ReadU16(self, offset): return self.Read(U16, offset)
  def ReadU32(self, offset): return self.Read(U32, offset)
  def ReadU64(self, offset): return self.Read(U64, offset)
  def ReadF32(self, offset): return self.Read(F32, offset)
  def ReadF64(self, offset): return self.Read(F64, offset)

  def WriteU8(self, offset, value):  self.Write(U8, offset, value)
  def WriteU16(self, offset, value): self.Write(U16, offset, value)
  def WriteU32(self, offset, value): self.Write(U32, offset, value)
  def WriteU64(self, offset, value): self.Write(U64, offset, value)
  def WriteF32(self, offset, value): self.Write(F32, offset, value)
  def WriteF64(self, offset, value): self.Write(F64, offset, value)


class MemoryBuffer(Memory):
  def __init__(self, num_bytes):
    Memory.__init__(self)
    self.data = ctypes.create_string_buffer(num_bytes)
    self.num_bytes = num_bytes

  def Resize(self, new_num_bytes):
    new_data = ctypes.create_string_buffer(new_num_bytes)
    ctypes.memmove(new_data, self.data, min(self.num_bytes, new_num_bytes))
    self.data = new_data
    self.num_bytes = new_num_bytes

  def Read(self, typ, offset):
    return struct.unpack_from(TYPE_TO_PACK_FMT[typ], self.data, offset)[0]

  def Write(self, typ, offset, value):
    struct.pack_into(TYPE_TO_PACK_FMT[typ], self.data, offset, value)


class NullMemory(Memory):
  def Read(self, typ, offset):
    return 0

  def Write(self, typ, offset, value):
    pass


class MemoryWriter(object):
  def __init__(self, memory, offset=0):
    self.offset = offset
    self.memory = memory

  def Write(self, typ, value):
    self.memory.Write(typ, self.offset, value)
    self.offset += SIZEOF_TYPE[typ]

  def WriteU8(self, value):  self.Write(U8, value)
  def WriteU16(self, value): self.Write(U16, value)
  def WriteU32(self, value): self.Write(U32, value)
  def WriteU64(self, value): self.Write(U64, value)
  def WriteF32(self, value): self.Write(F32, value)
  def WriteF64(self, value): self.Write(F64, value)

  def Skip(self, num_bytes):
    self.offset += num_bytes

  def Align(self, alignment):
    self.offset = Align(self.offset, alignment)
