#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import optparse
import sys

import memory
import module


ADDRESS_SOURCE_MASK   = 0xC0000000
ADDRESS_SOURCE_GLOBAL = 0x00000000
ADDRESS_SOURCE_HEAP   = 0x40000000
ADDRESS_SOURCE_STACK  = 0x80000000
ADDRESS_POINTER_MASK  = 0x3fffffff

FN_HIGH_BIT = 0x80000000
FN_NACL_IRT_QUERY = FN_HIGH_BIT + 0

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

def log_fn(fn):
  def decorator(*args):
    arg_kv = ', '.join('%s=%r' % (fn.__code__.co_varnames[i], args[i])
                       for i in range(len(args)))
    print '>>> %s(%s)' % (fn.__name__, arg_kv)
    return fn(*args)
  return decorator

@extend(module.ModuleBlock)
class ModuleBlock(object):
  def GetFunctionByName(self, name):
    for fn in self.functions:
      if fn.name == name:
        return fn
    return None

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

  def GetMemSize(self, argv=None, envp=None):
    writer = memory.MemoryWriter(memory.NullMemory())
    return self.InitializeMemory(writer, argv, envp)

  def InitializeMemory(self, writer, argv=None, envp=None):
    argv = argv or []
    envp = envp or []

    fixups = []
    writer.WriteU32(0)  # For NULL address
    self._WriteStartInfo(writer, argv, envp)
    self._WriteAll(self.Constants(), writer, fixups)
    self._WriteAll(self.NonConsts(), writer, fixups)
    for fixup in fixups:
      fixup()
    return writer.offset

  def _WriteStartInfo(self, writer, argv, envp):
    # From nacl_startup.h in the native_client repo:
    #
    # The true entry point for untrusted code is called with the normal C ABI,
    # taking one argument.  This is a pointer to stack space containing these
    # words:
    #      [0]             cleanup function pointer (always NULL in actual startup)
    #      [1]             envc, count of envp[] pointers
    #      [2]             argc, count of argv[] pointers
    #      [3]             argv[0..argc] pointers, argv[argc] being NULL
    #      [3+argc]        envp[0..envc] pointers, envp[envc] being NULL
    #      [3+argc+envc]   auxv[] pairs
    #
    writer.WriteU32(0)
    writer.WriteU32(len(envp))
    writer.WriteU32(len(argv))
    # Write pointers to argv/envp values. These will need to be fixed up after
    # we write out everything else.

    #argv
    argv_ptr_offset = writer.offset
    writer.Skip((len(argv) + 1) * 4)  # +1 for NULL entry
    # envp
    envp_ptr_offset = writer.offset
    writer.Skip((len(envp) + 1) * 4)  # +1 for NULL entry
    # auxv
    self._WriteAuxv(writer)

    # Now write the argv/envp string values, and the pointers to these
    # strings.
    self._WriteStringArray(writer, argv, argv_ptr_offset)
    self._WriteStringArray(writer, envp, envp_ptr_offset)

  def _WriteStringArray(self, writer, array, ptr_offset):
    for item in array:
      offset = writer.offset
      # Write the value.
      for c in item:
        writer.WriteU8(ord(c))
      writer.WriteU8(0)  # Null terminator.

      # Now write the pointer
      writer.memory.WriteU32(ptr_offset, offset)
      ptr_offset += 4


  def _WriteAuxv(self, writer):
    # The expected auxv structure is key/value pairs.
    # From elf_auxv.h in the native_client repo:
    #
    #   name       value  description
    #   AT_NULL    0      Terminating item in an auxv array
    #   AT_ENTRY   9      Entry point of the executable
    #   AT_SYSINFO 32     System entry call point
    #
    # In reality, the AT_SYSINFO value is the only one we care about, and it
    # is the address of the __nacl_irt_query function:
    #
    # typedef size_t (*TYPE_nacl_irt_query)(const char *interface_ident,
    #                                       void *table, size_t tablesize);
    writer.WriteU32(32)  # AT_SYSINFO
    writer.WriteU32(FN_NACL_IRT_QUERY)
    writer.WriteU32(0)  # AT_NULL

  def _WriteAll(self, generator, writer, fixups):
    for var in generator:
      writer.Align(var.alignment)
      var.Write(writer, fixups)


@extend(module.GlobalVar)
class GlobalVar(object):
  def Write(self, writer, fixups):
    self.offset = writer.offset
    for initializer in self.initializers:
      initializer.Write(writer, fixups)


@extend(module.Function)
class Function(object):
  alignment = 4

  def Write(self, writer, fixups):
    self.offset = writer.offset
    writer.WriteU32(self.index)


@extend(module.ZeroFillInitializer)
class ZeroFillInitializer(object):
  def Write(self, writer, fixups):
    for _ in range(self.num_bytes):
      writer.WriteU8(0)


@extend(module.DataInitializer)
class DataInitializer(object):
  def Write(self, writer, fixups):
    for byte in self.data:
      writer.WriteU8(byte)


@extend(module.RelocInitializer)
class RelocInitializer(object):
  def Write(self, writer, fixups):
    offset = writer.offset

    def FixupFn():
      if isinstance(self.base_val, module.GlobalVarValue):
        writer.memory.WriteU32(offset, self.base_val.var.offset)
      elif isinstance(self.base_val, module.FunctionValue):
        writer.memory.WriteU32(offset, self.base_val.function.index)
      else:
        raise module.Error('Unknown reloc base_val %s' % self.base_val)

    fixups.append(FixupFn)
    writer.Skip(4)


@extend(module.IntegerConstantValue)
class IntegerConstantValue(object):
  def GetValue(self, context):
    return self.value


@extend(module.InstructionValue)
class InstructionValue(object):
  def GetValue(self, context):
    return context.GetValue(self.inst.value_idx)


@extend(module.FunctionArgValue)
class FunctionArgValue(object):
  def GetValue(self, context):
    return context.GetValue(self.value_idx)


@extend(module.GlobalVarValue)
class GlobalVarValue(object):
  def GetValue(self, context):
    return self.var.offset

@extend(module.FunctionValue)
class FunctionValue(object):
  def GetValue(self, context):
    # Get the "address" of this function. Because the function doesn't
    # actually exist in memory, we just the index as an ID.
    return self.function.index


@extend(module.AllocaInstruction)
class AllocaInstruction(object):
  def Execute(self, context):
    size = self.size.GetValue(context)
    address = context.stack.Alloca(size, self.alignment)
    context.SetValue(self.value_idx, address)
    context.location.NextInstruction()

def ModuleTypeToMemoryType(typ):
  if isinstance(typ, module.IntegerType):
    if typ.width == 8:
      return memory.U8
    elif typ.width == 16:
      return memory.U16
    elif typ.width == 32:
      return memory.U32
    elif typ.width == 64:
      return memory.U64
  elif isinstance(typ, module.FloatType):
    return memory.F32
  elif isinstance(typ, module.DoubleType):
    return memory.F64
  elif isinstance(typ, module.FunctionType):
    # Value is returned as an address
    return memory.U32


@extend(module.StoreInstruction)
class StoreInstruction(object):
  def Execute(self, context):
    address = self.dest.GetValue(context)
    value = self.value.GetValue(context)
    typ = ModuleTypeToMemoryType(self.type)
    mem, address = context.GetMemoryFromAddress(address)
    if address == 0:
      raise module.Error('Writing to NULL pointer')
    mem.Write(typ, address, value)
    context.location.NextInstruction()


@extend(module.LoadInstruction)
class LoadInstruction(object):
  def Execute(self, context):
    address = self.source.GetValue(context)
    typ = ModuleTypeToMemoryType(self.type)
    mem, address = context.GetMemoryFromAddress(address)
    if address == 0:
      raise module.Error('Reading from NULL pointer')
    value = mem.Read(typ, address)
    context.SetValue(self.value_idx, value)
    context.location.NextInstruction()


@extend(module.BinOpInstruction)
class BinOpInstruction(object):
  def Execute(self, context):
    opval0 = self.opval0.GetValue(context)
    opval1 = self.opval1.GetValue(context)
    if self.opcode == module.BINOP_ADD:
      value = opval0 + opval1
    elif self.opcode == module.BINOP_SUB:
      value = opval0 - opval1
    elif self.opcode == module.BINOP_MUL:
      value = opval0 * opval1
    elif self.opcode == module.BINOP_OR:
      value = opval0 | opval1
    elif self.opcode == module.BINOP_AND:
      value = opval0 & opval1
    elif self.opcode == module.BINOP_SHL:
      value = opval0 << opval1
    else:
      raise module.Error('Unimplemented binop: %s' % self.opcode)
    context.SetValue(self.value_idx, value)
    context.location.NextInstruction()


@extend(module.BrInstruction)
class BrInstruction(object):
  def Execute(self, context):
    if self.cond:
      value = self.cond.GetValue(context)
    else:
      value = True

    if value:
      next_bb = self.true_bb
    else:
      next_bb = self.false_bb
    context.location.GotoBlock(next_bb)


@extend(module.PhiInstruction)
class PhiInstruction(object):
  def Execute(self, context):
    last_bb_idx = context.location.last_bb_idx
    for incoming in self.incoming:
      if incoming.bb == last_bb_idx:
        value = incoming.value.GetValue(context)
        break
    else:
      raise module.Error('Unknown incoming bb: %s' % last_bb_idx)
    context.SetValue(self.value_idx, value)
    context.location.NextInstruction()


@extend(module.SwitchInstruction)
class SwitchInstruction(object):
  def Execute(self, context):
    value = self.cond.GetValue(context)
    for case in self.cases:
      for item in case.items:
        if item.IsValueInRange(value):
          context.location.GotoBlock(case.dest_bb)
          return
    context.location.GotoBlock(self.default_bb)


@extend(module.CastInstruction)
class CastInstruction(object):
  def Execute(self, context):
    opval = self.opval.GetValue(context)
    if self.opcode in (module.CAST_TRUNC, module.CAST_ZEXT):
      assert isinstance(self.type, module.IntegerType)
      value = opval & ((1 << self.type.width) - 1)
    else:
      raise module.Error('Unimplemented cast: %s' % self.opcode)
    context.SetValue(self.value_idx, value)
    context.location.NextInstruction()


@extend(module.Cmp2Instruction)
class Cmp2Instruction(object):
  def Execute(self, context):
    opval0 = self.opval0.GetValue(context)
    opval1 = self.opval1.GetValue(context)
    if self.predicate == module.ICMP_EQ:
      assert type(opval0) in (int, long)
      assert type(opval1) in (int, long)
      value = 1 if opval0 == opval1 else 0
    elif self.predicate == module.ICMP_SGT:
      assert type(opval0) in (int, long)
      assert type(opval1) in (int, long)
      value = 1 if opval0 > opval1 else 0
    elif self.predicate == module.ICMP_UGT:
      assert type(opval0) in (int, long)
      assert type(opval1) in (int, long)
      value = 1 if opval0 > opval1 else 0
    else:
      raise module.Error('Unimplemented cmp2: %s' % self.predicate)
    context.SetValue(self.value_idx, value)
    context.location.NextInstruction()


@extend(module.CallInstruction)
class CallInstruction(object):
  def Execute(self, context):
    values = []
    for arg in self.args:
      values.append(arg.GetValue(context))

    if self.is_indirect:
      function_idx = self.callee.GetValue(context)

      if function_idx & FN_HIGH_BIT:
        # This is a built-in function (IRT)
        function_idx &= ~FN_HIGH_BIT
        result = builtin_functions[function_idx](context, *values)
        context.SetValue(self.value_idx, result)
        context.location.NextInstruction()
        return

      if function_idx >= len(context.module.functions):
        print 'Attempting to call non-existent function %d. (only %d)' % (
            function_idx, len(context.module.functions))
      function = context.module.functions[function_idx]
    else:
      function = self.callee.function
      if function.name:
        intrinsic = intrinsics.get(function.name)
        if not intrinsic:
          raise module.Error('Unimplemented intrinsic: %s' % function.name)

        result = intrinsic(context, *values)
        if result:
          context.SetValue(self.value_idx, result)
        context.location.NextInstruction()
        return

    context.EnterFunction(function)
    for i, value in enumerate(values):
      context.SetArgValue(i, value)


@extend(module.RetInstruction)
class RetInstruction(object):
  def Execute(self, context):
    if self.opval:
      value = self.opval.GetValue(context)
      context.ExitFunction()
      context.SetValue(context.location.inst.value_idx, value)
    else:
      context.ExitFunction()
    context.location.NextInstruction()


@extend(module.VSelectInstruction)
class VSelectInstruction(object):
  def Execute(self, context):
    value = self.cond.GetValue(context)
    if value:
      context.SetValue(self.value_idx, self.trueval.GetValue(context))
    else:
      context.SetValue(self.value_idx, self.falseval.GetValue(context))
    context.location.NextInstruction()


# Built-in functions (IRT) #

@log_fn
def nacl_irt_query(context, name_p, table_p, table_size):
  name_mem, name_address = context.GetMemoryFromAddress(name_p)
  name = memory.ReadCString(name_mem, name_address)

  print '>>> nacl_irt_query(%s)' % name

  table_mem, table_address = context.GetMemoryFromAddress(table_p)

  def BuiltinFunctionToId(fn):
    try:
      index = builtin_functions.index(fn)
    except ValueError:
      raise module.Error('Function not in builtin_functions')
    return FN_HIGH_BIT | index

  def WriteTable(iface):
    writer = memory.MemoryWriter(table_mem, table_address)
    count = min(table_size / 4, len(iface))
    for i in range(count):
      fn_id = BuiltinFunctionToId(iface[i])
      writer.WriteU32(fn_id)
    return count * 4

  iface = nacl_irt_query_map.get(name)
  if iface:
    return WriteTable(iface)
  return 0

# nacl-irt-basic-0.1 interface #
@log_fn
def nacl_irt_basic_exit(context, status):
  sys.exit(status)

@log_fn
def nacl_irt_basic_gettod(context, timeval_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_basic_clock(context, ticks_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_basic_nanosleep(context, req_p, rem_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_basic_sched_yield(context):
  return 38  # ENOSYS

@log_fn
def nacl_irt_basic_sys_conf(context, name_p, value_p):
  return 38  # ENOSYS

# nacl-irt-fdio-0.1 interface #
@log_fn
def nacl_irt_fdio_close(context, fd):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_dup(context, fd, newfd_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_dup2(context, fd, newfd):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_read(context, fd, buf_p, count, nread_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_write(context, fd, buf_p, count, nwrote_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_seek(context, fd, offset, whence, new_offset_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_fstat(context, fd, stat_p):
  return 38  # ENOSYS

@log_fn
def nacl_irt_fdio_getdents(context, fd, dirent_p, count, nread_p):
  return 38  # ENOSYS

# nacl-irt-memory-0.3 interface #
@log_fn
def nacl_irt_memory_mmap(context, addr_pp, len_, prot, flags, fd, off):
  if (flags & 0x20) != 0x20:  # MAP_ANONYMOUS
    return 22  # EINVAL

  # TODO(binji): less-stupid mmap
  size = context.heap.memory.num_bytes
  new_size = size + len_
  context.heap.Resize(new_size)
  address = ADDRESS_SOURCE_HEAP | size

  mem, addr_pp = context.GetMemoryFromAddress(addr_pp)
  mem.WriteU32(addr_pp, address)
  return 0

@log_fn
def nacl_irt_memory_munmap(context, addr, len_):
  return 38  # ENOSYS

@log_fn
def nacl_irt_memory_mprotect(context, addr, len_, prot):
  return 38  # ENOSYS

# nacl-irt-tls-0.1 interface #
@log_fn
def nacl_irt_tls_init(context, thread_ptr_p):
  context.tls_p = thread_ptr_p
  return 0

@log_fn
def nacl_irt_tls_get(context):
  return context.tls_p

nacl_irt_basic_0_1 = [
  nacl_irt_basic_exit,
  nacl_irt_basic_gettod,
  nacl_irt_basic_clock,
  nacl_irt_basic_nanosleep,
  nacl_irt_basic_sched_yield,
  nacl_irt_basic_sys_conf,
]

nacl_irt_fdio_0_1 = [
  nacl_irt_fdio_close,
  nacl_irt_fdio_dup,
  nacl_irt_fdio_dup2,
  nacl_irt_fdio_read,
  nacl_irt_fdio_write,
  nacl_irt_fdio_seek,
  nacl_irt_fdio_fstat,
  nacl_irt_fdio_getdents,
]

nacl_irt_memory_0_3 = [
  nacl_irt_memory_mmap,
  nacl_irt_memory_munmap,
  nacl_irt_memory_mprotect,
]

nacl_irt_tls_0_1 = [
  nacl_irt_tls_init,
  nacl_irt_tls_get,
]

nacl_irt_query_map = {
  'nacl-irt-basic-0.1': nacl_irt_basic_0_1,
  'nacl-irt-fdio-0.1': nacl_irt_fdio_0_1,
  'nacl-irt-memory-0.3': nacl_irt_memory_0_3,
  'nacl-irt-tls-0.1': nacl_irt_tls_0_1,
}

builtin_functions = [
  nacl_irt_query
]

def AddInterface(iface):
  for fn in iface:
    builtin_functions.append(fn)

AddInterface(nacl_irt_basic_0_1)
AddInterface(nacl_irt_fdio_0_1)
AddInterface(nacl_irt_memory_0_3)
AddInterface(nacl_irt_tls_0_1)


# Intrinsics #

@log_fn
def llvm_nacl_atomic_load_i32(context, addr_p, flags):
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  if addr_p == 0:
    raise module.Error('Reading from NULL pointer')
  return mem.Read(memory.U32, addr_p)

@log_fn
def llvm_nacl_read_tp(context):
  return context.tls_p

@log_fn
def llvm_memcpy_p0i8_p0i8_i32(context, dst_p, src_p, len_, align, isvolatile):
  dst_mem, dst_p = context.GetMemoryFromAddress(dst_p)
  src_mem, src_p = context.GetMemoryFromAddress(src_p)
  # TODO(binji): optimize
  for off in range(len_):
    value = dst_mem.ReadU8(dst_p + off)
    src_mem.WriteU8(src_p + off, value)


intrinsics = {
  'llvm.nacl.atomic.load.i32': llvm_nacl_atomic_load_i32,
  'llvm.nacl.read.tp': llvm_nacl_read_tp,
  'llvm.memcpy.p0i8.p0i8.i32': llvm_memcpy_p0i8_p0i8_i32,
}

###############################################################################


class Location(object):
  def __init__(self):
    self.function = None
    self.bb = None
    self.bb_idx = None
    self.last_bb_idx = None
    self.inst_idx = None
    self.inst = None

  def UpdateInstruction(self):
    self.inst = self.bb.instructions[self.inst_idx]

  def NextInstruction(self):
    self.inst_idx += 1
    self.UpdateInstruction()

  def GotoBlock(self, bb_idx):
    self.last_bb_idx = self.bb_idx
    self.bb_idx = bb_idx
    self.bb = self.function.basic_blocks[bb_idx]
    self.inst_idx = 0
    self.UpdateInstruction()

  def GotoFunction(self, function):
    self.function = function
    self.GotoBlock(0)


class Stack(object):
  def __init__(self, stack_size):
    self.memory = memory.Memory(stack_size)
    self.frames = []
    self.top = 4  # Skip NULL address

  def EnterFunction(self, location, values):
    self.frames.append(CallFrame(location, values, self.top))

  def ExitFunction(self):
    frame = self.frames[-1]
    self.frames.pop()
    self.top = frame.top
    return frame.location, frame.values

  def Alloca(self, size, alignment):
    self.top = memory.Align(self.top, alignment)
    result = self.top
    self.top += size
    return ADDRESS_SOURCE_STACK | result


class CallFrame(object):
  def __init__(self, location, values, top):
    self.location = copy.copy(location)
    self.values = values  # reference, don't copy. These won't be changed.
    self.top = top


class GlobalMemory(object):
  def __init__(self, mod):
    self.memory = memory.Memory(mod.GetMemSize())
    writer = memory.MemoryWriter(self.memory)
    mod.InitializeMemory(writer)


class Heap(object):
  def __init__(self, init_size):
    self.memory = memory.Memory(init_size)

  def Resize(self, new_size):
    self.memory.Resize(new_size)


class Context(object):
  def __init__(self, mod, stack_size):
    self.module = mod
    self.stack = Stack(stack_size)
    self.heap = Heap(4)  # Skip the NULL address
    self.global_memory = GlobalMemory(mod)
    self.location = Location()
    self.values = None
    self.EnterFunction(mod.GetFunctionByName('_start'))

  def EnterFunction(self, function):
    self.stack.EnterFunction(self.location, self.values)
    self.location.GotoFunction(function)
    # Allocate space for all function values
    num_values = len(function.type.argtypes)
    num_values += len(function.values)
    self.values = [None] * num_values

  def ExitFunction(self):
    self.location, self.values = self.stack.ExitFunction()

  def SetValue(self, idx, value):
    offset = self.location.function.value_idx_offset
    self.values[idx - offset] = value

  def SetArgValue(self, idx, value):
    assert 0 <= idx < len(self.location.function.type.argtypes)
    self.values[idx] = value

  def GetValue(self, idx):
    offset = self.location.function.value_idx_offset
    assert idx - offset >= 0
    return self.values[idx - offset]

  def GetMemoryFromAddress(self, address):
    address_source = address & ADDRESS_SOURCE_MASK
    if address_source == ADDRESS_SOURCE_GLOBAL:
      mem = self.global_memory.memory
    elif address_source == ADDRESS_SOURCE_STACK:
      mem = self.stack.memory
    elif address_source == ADDRESS_SOURCE_HEAP:
      mem = self.heap.memory
    else:
      raise module.Error('Invalid address source %x' % address_source)
    return mem, address & ADDRESS_POINTER_MASK


def Run(mod, stack_size):
  context = Context(mod, stack_size)
  # First arg is the address of the init structure. We always initialize it to
  # 4.
  context.SetArgValue(0, 4)
  last_bb_idx = None
  while True:
    if context.location.bb_idx != last_bb_idx:
      print 'Block %s' % context.location.bb_idx
      last_bb_idx = context.location.bb_idx
    inst = context.location.inst
    print inst
    inst.Execute(context)
    if inst.HasValue():
      print '  %%%s = %s' % (inst.value_idx, context.GetValue(inst.value_idx))


def main(args):
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  if not args:
    parser.error('Expected file')

  m = module.Read(open(args[0]))
  Run(m, 128)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
