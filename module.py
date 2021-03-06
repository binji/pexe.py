#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import sys

import bitcode

BLOCKID_BLOCKINFO = 0
BLOCKID_MODULE = 8
BLOCKID_CONSTANTS = 11
BLOCKID_FUNCTION = 12
BLOCKID_VALUE_SYMTAB = 14
BLOCKID_TYPE = 17
BLOCKID_GLOBALVAR = 19

MODULE_CODE_VERSION = 1
MODULE_CODE_FUNCTION = 8

TYPE_CODE_NUMENTRY = 1
TYPE_CODE_VOID = 2
TYPE_CODE_FLOAT = 3
TYPE_CODE_DOUBLE = 4
TYPE_CODE_INTEGER = 7
TYPE_CODE_FUNCTION = 21

VST_CODE_ENTRY = 1
VST_CODE_BBENTRY = 2

CST_CODE_SETTYPE = 1
CST_CODE_UNDEF = 3
CST_CODE_INTEGER = 4
CST_CODE_FLOAT = 6

GLOBALVAR_VAR = 0
GLOBALVAR_COMPOUND = 1
GLOBALVAR_ZEROFILL = 2
GLOBALVAR_DATA = 3
GLOBALVAR_RELOC = 4
GLOBALVAR_COUNT = 5

CAST_TRUNC = 0
CAST_ZEXT = 1
CAST_SEXT = 2
CAST_FPTOUI = 3
CAST_FPTOSI = 4
CAST_UITOFP = 5
CAST_SITOFP = 6
CAST_FPTRUNC = 7
CAST_FPEXT = 8
CAST_BITCAST = 11
cast_name = dict((v, k[5:].lower()) for k, v in vars().iteritems()
                  if k.startswith('CAST_'))

BINOP_ADD = 0
BINOP_SUB = 1
BINOP_MUL = 2
BINOP_UDIV = 3
BINOP_SDIV = 4
BINOP_UREM = 5
BINOP_SREM = 6
BINOP_SHL = 7
BINOP_LSHR = 8
BINOP_ASHR = 9
BINOP_AND = 10
BINOP_OR = 11
BINOP_XOR = 12
binop_name = dict((v, k[6:].lower()) for k, v in vars().iteritems()
                  if k.startswith('BINOP_'))

OBO_NO_UNSIGNED_WRAP = 0
OBO_NO_SIGNED_WRAP = 1

PEO_EXACT = 0

FPO_UNSAFE_ALGEBRA = 0
FPO_NO_NANS = 1
FPO_NO_INFS = 2
FPO_NO_SIGNED_ZEROS = 3
FPO_ALLOW_RECIPROCAL = 4

FUNC_CODE_DECLAREBLOCKS = 1
FUNC_CODE_INST_BINOP = 2
FUNC_CODE_INST_CAST = 3
FUNC_CODE_INST_RET = 10
FUNC_CODE_INST_BR = 11
FUNC_CODE_INST_SWITCH = 12
FUNC_CODE_INST_UNREACHABLE = 15
FUNC_CODE_INST_PHI = 16
FUNC_CODE_INST_ALLOCA = 19
FUNC_CODE_INST_LOAD = 20
FUNC_CODE_INST_STORE = 24
FUNC_CODE_INST_CMP2 = 28
FUNC_CODE_INST_VSELECT = 29
FUNC_CODE_INST_CALL = 34
FUNC_CODE_INST_FORWARDTYPEREF = 43
FUNC_CODE_INST_CALL_INDIRECT = 44

FCMP_FALSE = 0
FCMP_OEQ = 1
FCMP_OGT = 2
FCMP_OGE = 3
FCMP_OLT = 4
FCMP_OLE = 5
FCMP_ONE = 6
FCMP_ORD = 7
FCMP_UNO = 8
FCMP_UEQ = 9
FCMP_UGT = 10
FCMP_UGE = 11
FCMP_ULT = 12
FCMP_ULE = 13
FCMP_UNE = 14
FCMP_TRUE = 15
ICMP_EQ = 32
ICMP_NE = 33
ICMP_UGT = 34
ICMP_UGE = 35
ICMP_ULT = 36
ICMP_ULE = 37
ICMP_SGT = 38
ICMP_SGE = 39
ICMP_SLT = 40
ICMP_SLE = 41
cmp_name = dict((v, k.lower()) for k, v in vars().iteritems()
                if k.startswith(('FCMP', 'ICMP')))


def DecodeSignRotatedValue(x):
  if (x & 1) == 0:
    return x >> 1
  if x != 1:
    return -(x >> 1)
  return -(1 << 31)


class Error(Exception):
  pass


class Context(object):
  def __init__(self):
    self.values_mark = None
    self.use_relative_ids = None
    self.types = []
    self.values = []
    self.value_fixups = {}
    # This will be a reference to a list of all basic blocks for the
    # function currently being parsed
    self.basic_blocks = None
    self.global_vars = []

  def MarkValues(self):
    assert self.values_mark is None
    self.values_mark = len(self.values)

  def ResetValues(self):
    assert self.values_mark is not None
    del self.values[self.values_mark:]
    self.values_mark = None

  def FunctionValues(self):
    assert self.values_mark is not None
    return self.values[self.values_mark:]

  def AppendValue(self, value):
    self.values.append(value)
    new_idx = len(self.values) - 1
    self.FixupValues(new_idx, value)

  def FixupValues(self, idx, value):
    if idx in self.value_fixups:
      for fn in self.value_fixups[idx]:
        fn(value)
      del self.value_fixups[idx]

  def GetOrCreateValue(self, idx, fixup_fn):
    if idx >= len(self.values):
      self.value_fixups.setdefault(idx, []).append(fixup_fn)
      return None
    return self.values[idx]

  def GetRelativeIndex(self, idx):
    if not self.use_relative_ids:
      return idx

    # record values are always unsigned 64-bit. Treat idx as a 32-bit
    # signed value.
    if idx >= 0x80000000:
      idx = 0x100000000 - idx
    return len(self.values) - idx

  def GetValueRelative(self, idx):
    return self.values[self.GetRelativeIndex(idx)]

  def GetOrCreateValueRelative(self, idx, fixup_fn):
    return self.GetOrCreateValue(self.GetRelativeIndex(idx), fixup_fn)


class Value(object):
  pass

class FunctionValue(Value):
  def __init__(self, record, context, index):
    self.index = index
    self.type = context.types[record.values[0]]
    self.calling_conv = record.values[1]
    self.is_proto = record.values[2]
    self.linkage = record.values[3]

  def __repr__(self):
    if hasattr(self, 'name'):
      return '<%%%s: Function %s %s>' % (self.index, self.name, self.type)
    return '<%%%s: Function %s>' % (self.index, self.type)

class FunctionArgValue(Value):
  def __init__(self, idx, curtype):
    self.type = curtype
    self.arg_index = idx

  def __repr__(self):
    return '<Function Arg %d %s>' % (self.arg_index, self.type)

class UndefConstantValue(Value):
  def __init__(self, curtype):
    self.type = curtype

  def __repr__(self):
    return '<Undef Constant %s>' % self.type

class IntegerConstantValue(Value):
  def __init__(self, record, curtype):
    if not isinstance(curtype, IntegerType):
      raise Error('Expected integer type')
    self.type = curtype
    self.value = DecodeSignRotatedValue(record.values[0])

  def __repr__(self):
    return '<Integer Constant %d>' % self.value

class FloatConstantValue(Value):
  def __init__(self, record, curtype):
    if not isinstance(curtype, (FloatType, DoubleType)):
      raise Error('Expected float type')
    self.type = curtype
    self.value = record.values[0]

  def __repr__(self):
    return '<Float Constant %f>' % self.value

class InstructionValue(Value):
  def __init__(self, inst):
    self.inst = inst

  def __repr__(self):
    return '<%%%s Value>' % self.inst.value_idx

class GlobalVarValue(Value):
  def __init__(self, var):
    self.var = var

  def __repr__(self):
    return '<%%%s Global Value>' % self.var.index


class Type(object):
  pass

class VoidType(Type):
  def __repr__(self):
    return 'void'

class FloatType(Type):
  def __repr__(self):
    return 'float'

class DoubleType(Type):
  def __repr__(self):
    return 'double'

class IntegerType(Type):
  def __init__(self, record):
    self.width = record.values[0]

  def __repr__(self):
    return 'int%d' % self.width

class FunctionType(Type):
  def __init__(self, record, context):
    self.varargs = record.values[0] != 0
    self.rettype = context.types[record.values[1]]
    self.argtypes = [context.types[x] for x in record.values[2:]]

  def __repr__(self):
    args = map(repr, self.argtypes)
    if self.varargs:
      args.append('...')
    return '%s(%s)' % (self.rettype, ', '.join(args))


class GlobalVar(object):
  def __init__(self, record, index):
    self.index = index
    self.alignment = (1 << record.values[0]) >> 1
    self.is_constant = record.values[1] != 0
    self.initializers = []

  def AppendInitializer(self, initializer):
    self.initializers.append(initializer)

  def __repr__(self):
    const_str = ' const' if self.is_constant else ''
    return '<%%%s: GlobalVar %s align=%d%s>' % (
        self.index, ', '.join(map(repr, self.initializers)),
        self.alignment, const_str)


class Initializer(object):
  pass

class ZeroFillInitializer(Initializer):
  def __init__(self, record):
    self.num_bytes = record.values[0]

  def __repr__(self):
    return '<Zero %d>' % self.num_bytes

class DataInitializer(Initializer):
  def __init__(self, record):
    self.data = record.values[:]

  def __repr__(self):
    return '<Data %d bytes>' % len(self.data)

class RelocInitializer(Initializer):
  def __init__(self, record, context):
    def fixup(value):
      self.base_val = value

    idx = record.values[0]
    self.base_val = context.GetOrCreateValue(idx, fixup)
    self.addend = 0
    if len(record.values) == 2:
      self.addend = record.values[1]

  def __repr__(self):
    if self.addend:
      return '<Reloc %s + %d>' % (self.base_val, self.addend)
    return '<Reloc %s>' % self.base_val


class Function(object):
  def __init__(self, value):
    self.value = value
    self.values = None
    self.basic_blocks = []


class BasicBlock(object):
  def __init__(self):
    self.instructions = []


class Instruction(object):
  def __init__(self):
    self.value_idx = None

  def IsTerminator(self):
    return False

  def HasValue(self):
    return True

  def __repr__(self):
    if self.value_idx is not None:
      return '<%%%s: %s>' % (self.value_idx, self.Repr())
    return '<%s>' % self.Repr()

  def Repr(self):
    return 'None'

class BinOpInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.opval0 = context.GetValueRelative(record.values[0])
    self.opval1 = context.GetValueRelative(record.values[1])
    self.opcode = record.values[2]
    if len(record.values) == 4:
      flags = record.values[3]
      if self.opcode in (BINOP_ADD, BINOP_SUB, BINOP_MUL, BINOP_SHL):
        self.no_signed_wrap = (flags & (1 << OBO_NO_SIGNED_WRAP)) != 0
        self.no_unsigned_wrap = (flags & (1 << OBO_NO_UNSIGNED_WRAP)) != 0
      elif self.opcode in (BINOP_SDIV, BINOP_UDIV, BINOP_LSHR, BINOP_ASHR):
        self.is_exact = (flags & (1 << PEO_EXACT)) != 0
      else:
        # TODO(binji): handle fast-math flags.
        pass

  def Repr(self):
    return 'BinOp %s %s %s' % (
        binop_name[self.opcode], self.opval0, self.opval1)

class CastInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.opval = context.GetValueRelative(record.values[0])
    self.desttype = context.types[record.values[1]]
    self.opcode = record.values[2]

  def Repr(self):
    return 'Cast %s %s = %s' % (
        cast_name[self.opcode], self.opval, self.desttype)

class VSelectInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.trueval = context.GetValueRelative(record.values[0])
    self.falseval = context.GetValueRelative(record.values[1])
    self.cond = context.GetValueRelative(record.values[2])

  def Repr(self):
    return 'VSelect %s ? %s : %s' % (self.cond, self.trueval, self.falseval)

class Cmp2Instruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.opval0 = context.GetValueRelative(record.values[0])
    self.opval1 = context.GetValueRelative(record.values[1])
    self.predicate = record.values[2]

  def Repr(self):
    return 'Cmp %s %s %s' % (cmp_name[self.predicate], self.opval0, self.opval1)

class RetInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.opval = None
    if len(record.values) == 1:
      self.opval = context.GetValueRelative(record.values[0])

  def IsTerminator(self):
    return True

  def Repr(self):
    if self.opval:
      return 'Ret %s' % self.opval
    return 'Ret'

class BrInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.true_bb = record.values[0]
    self.cond = None
    self.false_bb = None
    if len(record.values) > 1:
      self.false_bb = record.values[1]
      self.cond = context.GetValueRelative(record.values[2])

  def IsTerminator(self):
    return True

  def HasValue(self):
    return False

  def Repr(self):
    if self.false_bb:
      return 'Br %s ? %s : %s' % (self.cond, self.true_bb, self.false_bb)
    return 'Br %s' % self.true_bb

class SwitchInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.type = context.types[record.values[0]]
    self.cond = context.GetValueRelative(record.values[1])
    self.default_bb = record.values[2]
    value_gen = (x for x in record.values[3:])
    self.cases = []
    num_cases = next(value_gen)
    for _ in range(num_cases):
      self.cases.append(SwitchCase(value_gen))

  def IsTerminator(self):
    return True

  def HasValue(self):
    return False

  def Repr(self):
    return 'Switch %s %s default: %s %s' % (
        self.type, self.cond, self.default_bb, ' '.join(map(repr, self.cases)))

class SwitchCase(object):
  def __init__(self, value_gen):
    self.items = []
    num_items = next(value_gen)
    for _ in range(num_items):
      self.items.append(SwitchCaseItem(value_gen))
    self.dest_bb = next(value_gen)

  def __repr__(self):
    return '<%s => %s>' % (', '.join(map(repr, self.items)), self.dest_bb)

class SwitchCaseItem(object):
  def __init__(self, value_gen):
    is_single_number = next(value_gen)
    self.low = DecodeSignRotatedValue(next(value_gen))
    self.high = None
    if not is_single_number:
      self.high = DecodeSignRotatedValue(next(value_gen))

  def __repr__(self):
    if self.high:
      return '<%s..%s>' % (self.low, self.high)
    return '<%s>' % self.low

class UnreachableInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)

  def IsTerminator(self):
    return True

  def HasValue(self):
    return False

  def Repr(self):
    return 'Unreachable'

class PhiInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.type = context.types[record.values[0]]
    value_gen = (x for x in record.values[1:])
    self.incoming = []
    num_incoming = (len(record.values) - 1) / 2
    for _ in range(num_incoming):
      self.incoming.append(PhiIncoming(value_gen, context))

  def Repr(self):
    return 'Phi %s %s' % (self.type, ' '.join(map(repr, self.incoming)))

class PhiIncoming(object):
  def __init__(self, value_gen, context):
    def fixup(value):
      self.value = value

    if context.use_relative_ids:
      idx = DecodeSignRotatedValue(next(value_gen))
      self.value = context.GetOrCreateValueRelative(idx, fixup)
    else:
      self.value = context.GetOrCreateValue(idx, fixup)
    self.bb = next(value_gen)

  def __repr__(self):
    return '<%s => %s>' % (self.bb, self.value)

class AllocaInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.size = context.GetValueRelative(record.values[0])
    self.alignment = (1 << record.values[1]) >> 1

  def Repr(self):
    return 'Alloca %s align=%d' % (self.size, self.alignment)

class LoadInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.source = context.GetValueRelative(record.values[0])
    self.alignment = (1 << record.values[1]) >> 1
    self.type = context.types[record.values[2]]

  def Repr(self):
    return 'Load %s <= %s align=%d' % (self.type, self.source, self.alignment)

class StoreInstruction(Instruction):
  def __init__(self, record, context):
    Instruction.__init__(self)
    self.dest = context.GetValueRelative(record.values[0])
    self.value = context.GetValueRelative(record.values[1])
    self.alignment = (1 << record.values[2]) >> 1

  def HasValue(self):
    return False

  def Repr(self):
    return 'Store %s >= %s align=%d' % (self.value, self.dest, self.alignment)

class CallInstruction(Instruction):
  def __init__(self, record, context, is_indirect):
    Instruction.__init__(self)
    self.is_indirect = is_indirect
    cc_info = record.values[0]
    self.is_tail_call = (cc_info & 1) != 0
    self.calling_conv = cc_info >> 1
    self.callee = context.GetValueRelative(record.values[1])
    if not is_indirect and not isinstance(self.callee, FunctionValue):
      raise Error('Expected function value')

    value_gen = (x for x in record.values[2:])
    if is_indirect:
      self.rettype = context.types[next(value_gen)]
    else:
      self.type = self.callee.type
      self.rettype = self.type.rettype

      if not isinstance(self.type, FunctionType):
        raise Error('Expected function type')

    self.args = []
    for value in value_gen:
      self.args.append(context.GetValueRelative(value))

  def HasValue(self):
    return not isinstance(self.rettype, VoidType)

  def Repr(self):
    if self.args:
      arg_str = ' (%s)' % ', '.join(map(repr, self.args))
    else:
      arg_str = ''

    if self.is_indirect:
      return 'CallIndirect %s%s' % (self.callee, arg_str)
    else:
      if hasattr(self.callee, 'name'):
        # If we have a name its probably an intrinsic. The type doesn't
        # really help any.
        return 'Call %s%s' % (self.callee.name, arg_str)
      return 'Call %%%s%s' % (self.callee.index, arg_str)



# Blocks ######################################################################


class ModuleBlock(object):
  def __init__(self, block, context):
    self.version = None
    self.functions = []
    self.global_vars = []
    self.cur_function_idx = None

    for chunk in block.chunks:
      if isinstance(chunk, bitcode.Block):
        self.ParseBlock(chunk, context)
      elif isinstance(chunk, bitcode.Record):
        self.ParseRecord(chunk, context)
      else:
        raise Error('Bad chunk type')

  def ParseBlock(self, block, context):
    bid = block._id
    if bid == BLOCKID_BLOCKINFO:
      return
    elif bid == BLOCKID_TYPE:
      TypeBlock(block, context)
    elif bid == BLOCKID_GLOBALVAR:
      GlobalVarBlock(block, context)
      self.global_vars = context.global_vars[:]
    elif bid == BLOCKID_VALUE_SYMTAB:
      ValueSymtabBlock(block, context)
    elif bid == BLOCKID_FUNCTION:
      context.MarkValues()
      function = self.GetNextFunctionWithBody()
      FunctionBlock(block, context, function)
      context.ResetValues()
    else:
      raise Error('Bad block id %d' % bid)

  def ParseRecord(self, record, context):
    if record.code == MODULE_CODE_VERSION:
      self.version = record.values[0]
      context.use_relative_ids = self.version == 1
    elif record.code == MODULE_CODE_FUNCTION:
      index = len(context.values)
      value = FunctionValue(record, context, index)
      context.AppendValue(value)
      self.functions.append(Function(value))
    else:
      raise Error('Bad record code')

  def GetNextFunctionWithBody(self):
    if self.cur_function_idx is None:
      self.cur_function_idx = 0
    else:
      self.cur_function_idx += 1
    while self.functions[self.cur_function_idx].value.is_proto:
      self.cur_function_idx += 1
    return self.functions[self.cur_function_idx]


class TypeBlock(object):
  def __init__(self, block, context):
    for chunk in block.chunks:
      if not isinstance(chunk, bitcode.Record):
        raise Error('Unexpected chunk type')
      self.ParseRecord(chunk, context)

  def ParseRecord(self, record, context):
    if record.code == TYPE_CODE_VOID:
      context.types.append(VoidType())
    elif record.code == TYPE_CODE_FLOAT:
      context.types.append(FloatType())
    elif record.code == TYPE_CODE_DOUBLE:
      context.types.append(DoubleType())
    elif record.code == TYPE_CODE_INTEGER:
      context.types.append(IntegerType(record))
    elif record.code == TYPE_CODE_FUNCTION:
      context.types.append(FunctionType(record, context))
    elif record.code == TYPE_CODE_NUMENTRY:
      return
    else:
      raise Error('Bad record code')


class GlobalVarBlock(object):
  def __init__(self, block, context):
    record_gen = (x for x in block.chunks if isinstance(x, bitcode.Record))
    for record in record_gen:
      self.ParseRecord(record, record_gen, context)

  def ParseRecord(self, record, record_gen, context):
    if record.code == GLOBALVAR_VAR:
      num_initializers = 1
      index = len(context.values)
      var = GlobalVar(record, index)
      while num_initializers:
        record = next(record_gen)
        if record.code == GLOBALVAR_COMPOUND:
          num_initializers = record.values[0]
          continue
        elif record.code == GLOBALVAR_ZEROFILL:
          var.AppendInitializer(ZeroFillInitializer(record))
        elif record.code == GLOBALVAR_DATA:
          var.AppendInitializer(DataInitializer(record))
        elif record.code == GLOBALVAR_RELOC:
          var.AppendInitializer(RelocInitializer(record, context))
        else:
          raise Error('Bad record code')
        num_initializers -= 1
      context.global_vars.append(var)
      context.AppendValue(GlobalVarValue(var))
    elif record.code == GLOBALVAR_COUNT:
      return
    else:
      raise Error('Bad record code')


class ValueSymtabBlock(object):
  def __init__(self, block, context):
    for chunk in block.chunks:
      if not isinstance(chunk, bitcode.Record):
        raise Error('Unexpected chunk type')
      self.ParseRecord(chunk, context)

  def ParseRecord(self, record, context):
    if record.code == VST_CODE_ENTRY:
      value_id = record.values[0]
      name = record.values[1:]
      context.values[value_id].name = ''.join(name)
    elif record.code == VST_CODE_BBENTRY:
      bb_id = record.values[0]
      name = record.values[1:]
      context.basic_blocks[bb_id].name = ''.join(name)
    else:
      raise Error('Bad record code')


class FunctionBlock(object):
  def __init__(self, block, context, function):
    self.function = function
    context.basic_blocks = self.function.basic_blocks
    self.cur_bb_idx = 0

    self.AppendFunctionArgValues(context)

    try:
      for chunk in block.chunks:
        if isinstance(chunk, bitcode.Block):
          self.ParseBlock(chunk, context)
        elif isinstance(chunk, bitcode.Record):
          self.ParseRecord(chunk, context)
        else:
          raise Error('Bad chunk type')
    finally:
      context.basic_blocks = None

    # Copy all values from context
    self.function.values = context.FunctionValues()

  def AppendFunctionArgValues(self, context):
    func_type = self.function.value.type
    if not isinstance(func_type, FunctionType):
      raise Error('Expected function type')
    for i, argtype in enumerate(func_type.argtypes):
      context.AppendValue(FunctionArgValue(i, argtype))

  def ParseBlock(self, block, context):
    bid = block._id
    if bid == BLOCKID_CONSTANTS:
      ConstantsBlock(block, context)
    elif bid == BLOCKID_VALUE_SYMTAB:
      ValueSymtabBlock(block, context)
    else:
      raise Error('Bad block id %d' % bid)

  def ParseRecord(self, record, context):
    inst = None
    if record.code == FUNC_CODE_DECLAREBLOCKS:
      del self.function.basic_blocks[:]
      num_bbs = record.values[0]
      for _ in range(num_bbs):
        self.function.basic_blocks.append(BasicBlock())
      self.cur_bb_idx = 0
      return
    elif record.code == FUNC_CODE_INST_BINOP:
      inst = BinOpInstruction(record, context)
    elif record.code == FUNC_CODE_INST_CAST:
      inst = CastInstruction(record, context)
    elif record.code == FUNC_CODE_INST_VSELECT:
      inst = VSelectInstruction(record, context)
    elif record.code == FUNC_CODE_INST_CMP2:
      inst = Cmp2Instruction(record, context)
    elif record.code == FUNC_CODE_INST_RET:
      inst = RetInstruction(record, context)
    elif record.code == FUNC_CODE_INST_BR:
      inst = BrInstruction(record, context)
    elif record.code == FUNC_CODE_INST_SWITCH:
      inst = SwitchInstruction(record, context)
    elif record.code == FUNC_CODE_INST_UNREACHABLE:
      inst = UnreachableInstruction(record, context)
    elif record.code == FUNC_CODE_INST_PHI:
      inst = PhiInstruction(record, context)
    elif record.code == FUNC_CODE_INST_ALLOCA:
      inst = AllocaInstruction(record, context)
    elif record.code == FUNC_CODE_INST_LOAD:
      inst = LoadInstruction(record, context)
    elif record.code == FUNC_CODE_INST_STORE:
      inst = StoreInstruction(record, context)
    elif record.code == FUNC_CODE_INST_CALL:
      inst = CallInstruction(record, context, False)
    elif record.code == FUNC_CODE_INST_CALL_INDIRECT:
      inst = CallInstruction(record, context, True)
    elif record.code == FUNC_CODE_INST_FORWARDTYPEREF:
      return
    else:
      raise Error('Bad record code')

    cur_bb = self.function.basic_blocks[self.cur_bb_idx]
    cur_bb.instructions.append(inst)

    if inst and inst.IsTerminator():
      self.cur_bb_idx += 1

    if inst and inst.HasValue():
      inst.value_idx = len(context.values)
      context.AppendValue(InstructionValue(inst))


class ConstantsBlock(object):
  def __init__(self, block, context):
    self.curtype = None
    for chunk in block.chunks:
      if not isinstance(chunk, bitcode.Record):
        raise Error('Unexpected chunk type')
      self.ParseRecord(chunk, context)

  def ParseRecord(self, record, context):
    if record.code == CST_CODE_UNDEF:
      context.AppendValue(UndefConstantValue(self.curtype))
    elif record.code == CST_CODE_SETTYPE:
      self.curtype = context.types[record.values[0]]
    elif record.code == CST_CODE_INTEGER:
      context.AppendValue(IntegerConstantValue(record, self.curtype))
    elif record.code == CST_CODE_FLOAT:
      context.AppendValue(FloatConstantValue(record, self.curtype))
    else:
      raise Error('Bad record code')


def ParseBitCode(bitcode):
  context = Context()
  module_block = bitcode.blocks[0]
  return ModuleBlock(module_block, context)


def main(args):
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  if not args:
    parser.error('Expected file')

  bc = bitcode.Read(open(args[0]))
  module = ParseBitCode(bc)

  for var in module.global_vars:
    print 'Global %s' % var
  print
  for function in module.functions:
    if function.value.is_proto:
      continue
    print 'Function %s' % function.value
    for bbno, bb in enumerate(function.basic_blocks):
      print '  Block %d' % bbno
      for inst in bb.instructions:
        print '   ', inst
    print


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
