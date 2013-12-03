#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import sys

import memory
import module


# Hack some classes :)
def extend(cls):
  def decorator(newcls):
    for name, fn in newcls.__dict__.iteritems():
      if name.startswith('__'):
        continue
      if hasattr(cls, name):
        raise module.Error('Overwriting existing definition %s in %s' % (
                           name, cls))
      setattr(cls, name, fn)
  return decorator


@extend(module.ModuleBlock)
class ModuleBlock(object):
  def Constants(self):
    for fn in self.functions:
      yield fn
    for var in self.global_vars:
      if var.is_constant:
        yield var

  def NonConsts(self):
    for var in self.global_vars:
      if not var.is_constant:
        yield var

  def GetMemSize(self):
    writer = memory.NullMemoryWriter()
    self._WriteAll(self.Constants(), writer)
    self._WriteAll(self.NonConsts(), writer)
    return writer.offset

  def InitializeMemory(self, writer):
    self._WriteAll(self.Constants(), writer)
    self._WriteAll(self.NonConsts(), writer)
    writer.offset = 0
    self._WriteRelocAll(self.Constants(), writer)
    self._WriteRelocAll(self.NonConsts(), writer)

  def _WriteAll(self, generator, writer):
    for var in generator:
      writer.Align(var.alignment)
      var.Write(writer)

  def _WriteRelocAll(self, generator, writer):
    for var in generator:
      writer.Align(var.alignment)
      var.WriteReloc(writer)


@extend(module.GlobalVar)
class GlobalVar(object):
  def Write(self, writer):
    self.offset = writer.offset
    for initializer in self.initializers:
      initializer.Write(writer)

  def WriteReloc(self, writer):
    for initializer in self.initializers:
      initializer.WriteReloc(writer)


@extend(module.Function)
class Function(object):
  alignment = 4

  def Write(self, writer):
    self.offset = writer.offset
    writer.WriteU32(self.index)

  def WriteReloc(self, writer):
    writer.Skip(4)


@extend(module.ZeroFillInitializer)
class ZeroFillInitializer(object):
  def Write(self, writer):
    for _ in range(self.num_bytes):
      writer.WriteU8(0)

  def WriteReloc(self, writer):
    writer.Skip(self.num_bytes)


@extend(module.DataInitializer)
class DataInitializer(object):
  def Write(self, writer):
    for byte in self.data:
      writer.WriteU8(byte)

  def WriteReloc(self, writer):
    writer.Skip(len(self.data))


@extend(module.RelocInitializer)
class RelocInitializer(object):
  def Write(self, writer):
    writer.Skip(4)

  def WriteReloc(self, writer):
    if isinstance(self.base_val, module.GlobalVarValue):
      writer.WriteU32(self.base_val.var.offset)
    elif isinstance(self.base_val, module.FunctionValue):
      writer.WriteU32(self.base_val.function.offset)
    else:
      raise module.Error('Unknown reloc base_val %s' % self.base_val)


def main(args):
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  if not args:
    parser.error('Expected file')

  m = module.Read(open(args[0]))

  mem = memory.Memory(m.GetMemSize())
  writer = memory.MemoryWriter(mem)
  m.InitializeMemory(writer)
  print mem

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
