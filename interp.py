#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import ctypes
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
    return cls
  return decorator

def log_fn(fn):
  def decorator(*args):
    try:
      arg_kv = ', '.join('%s=%r' % (fn.__code__.co_varnames[i], args[i])
                         for i in range(len(args)))
    except IndexError:
      arg_kv = '???'
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
    return self.InitializeMemory(writer, argv, envp)[1]

  def InitializeMemory(self, writer, argv=None, envp=None):
    argv = argv or []
    envp = envp or []

    fixups = []
    writer.Skip(4)  # For NULL address
    self._WriteStartInfo(writer, argv, envp)
    self._WriteAll(self.NonConsts(), writer, fixups)
    constants_offset = writer.offset
    self._WriteAll(self.Constants(), writer, fixups)
    for fixup in fixups:
      fixup()
    return constants_offset, writer.offset

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
      if writer.offset:
        print '%%%d: %s' % (writer.offset, var)
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
        value = self.base_val.var.offset
      elif isinstance(self.base_val, module.FunctionValue):
        value = self.base_val.function.index
      else:
        raise module.Error('Unknown reloc base_val %s' % self.base_val)

      if self.addend:
        value += self.addend
      writer.memory.WriteU32(offset, value)

    fixups.append(FixupFn)
    writer.Skip(4)


@extend(module.IntegerConstantValue)
class IntegerConstantValue(object):
  def GetValue(self, context):
    return self.type.CastValue(self.value)


@extend(module.InstructionValue)
class InstructionValue(object):
  def GetValue(self, context):
    value = context.GetValue(self.inst.value_idx)
    return self.type.CastValue(value)


@extend(module.FunctionArgValue)
class FunctionArgValue(object):
  def GetValue(self, context):
    value = context.GetValue(self.value_idx)
    return self.type.CastValue(value)


@extend(module.GlobalVarValue)
class GlobalVarValue(object):
  def GetValue(self, context):
    return self.var.offset


@extend(module.FunctionValue)
class FunctionValue(object):
  def GetValue(self, context):
    # Get the "address" of this function. Because the function doesn't
    # actually exist in memory, we just use the index as an ID.
    return self.function.index


@extend(module.IntegerType)
class IntegerType(object):
  def _GetSignedCtype(self):
    return {
      8: ctypes.c_int8,
      16: ctypes.c_int16,
      32: ctypes.c_int32,
      64: ctypes.c_int64,
    }[self.width]

  def _GetUnsignedCtype(self):
    return {
      8: ctypes.c_uint8,
      16: ctypes.c_uint16,
      32: ctypes.c_uint32,
      64: ctypes.c_uint64,
    }[self.width]

  def CastValue(self, value, signed=False):
    if self.width == 1:
      return value & 1
    elif signed:
      return self._GetSignedCtype()(value).value
    else:
      return self._GetUnsignedCtype()(value).value


@extend(module.FloatType)
class FloatType(object):
  def CastValue(self, value):
    return ctypes.c_float(value).value


@extend(module.DoubleType)
class DoubleType(object):
  def CastValue(self, value):
    return ctypes.c_double(value).value


@extend(module.AllocaInstruction)
class AllocaInstruction(object):
  def Execute(self, context):
    size = self.size.GetValue(context)
    address = context.stack.Alloca(size, self.alignment)
    context.SetValue(self.type, self.value_idx, address)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.size]

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
    mem.Write(typ, address, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.value, self.dest]


@extend(module.LoadInstruction)
class LoadInstruction(object):
  def Execute(self, context):
    address = self.source.GetValue(context)
    typ = ModuleTypeToMemoryType(self.type)
    mem, address = context.GetMemoryFromAddress(address)
    value = mem.Read(typ, address)
    context.SetValue(self.type, self.value_idx, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.source]


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
    elif self.opcode == module.BINOP_XOR:
      value = opval0 ^ opval1
    elif self.opcode == module.BINOP_SHL:
      value = opval0 << opval1
    else:
      raise module.Error('Unimplemented binop: %s' % self.opcode)
    context.SetValue(self.type, self.value_idx, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.opval0, self.opval1]


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

  def GetValues(self):
    if self.cond:
      return [self.cond]
    return []


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
    context.SetValue(self.type, self.value_idx, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [i.value for i in self.incoming]


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

  def GetValues(self):
    return [self.cond]


@extend(module.CastInstruction)
class CastInstruction(object):
  def Execute(self, context):
    opval = self.opval.GetValue(context)

    if self.opcode in (module.CAST_TRUNC, module.CAST_ZEXT):
      value = opval
    elif self.opcode == module.CAST_SEXT:
      value = self.opval.type.CastValue(opval, signed=True)
    else:
      raise module.Error('Unimplemented cast: %s' % self.opcode)
    context.SetValue(self.type, self.value_idx, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.opval]


@extend(module.Cmp2Instruction)
class Cmp2Instruction(object):
  def Execute(self, context):
    opval0 = self.opval0.GetValue(context)
    opval1 = self.opval1.GetValue(context)

    value = None
    if module.ICMP_EQ <= self.predicate <= module.ICMP_ULE:
      opval0 = self.opval0.GetValue(context)
      opval1 = self.opval1.GetValue(context)
      if self.predicate == module.ICMP_EQ:
        value = 1 if opval0 == opval1 else 0
      elif self.predicate == module.ICMP_NE:
        value = 1 if opval0 != opval1 else 0
      elif self.predicate == module.ICMP_UGT:
        value = 1 if opval0 > opval1 else 0
      elif self.predicate == module.ICMP_UGE:
        value = 1 if opval0 >= opval1 else 0
      elif self.predicate == module.ICMP_ULT:
        value = 1 if opval0 < opval1 else 0
      elif self.predicate == module.ICMP_ULE:
        value = 1 if opval0 <= opval1 else 0
    elif module.ICMP_SGT <= self.predicate <= module.ICMP_SLE:
      opval0 = self.opval0.GetValue(context)
      opval1 = self.opval1.GetValue(context)
      # TODO(binji): cleaner way to do this?
      opval0 = self.opval0.type.CastValue(opval0, signed=True)
      opval1 = self.opval1.type.CastValue(opval1, signed=True)

      if self.predicate == module.ICMP_SGT:
        value = 1 if opval0 > opval1 else 0
      elif self.predicate == module.ICMP_SGE:
        value = 1 if opval0 >= opval1 else 0
      elif self.predicate == module.ICMP_SLT:
        value = 1 if opval0 < opval1 else 0
      elif self.predicate == module.ICMP_SLE:
        value = 1 if opval0 <= opval1 else 0

    if value is None:
      raise module.Error('Unimplemented cmp2: %s' % self.predicate)

    context.SetValue(self.type, self.value_idx, value)
    context.location.NextInstruction()

  def GetValues(self):
    return [self.opval0, self.opval1]


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
        context.SetValue(self.type, self.value_idx, result)
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
        if result is not None:
          context.SetValue(self.type, self.value_idx, result)
        context.location.NextInstruction()
        return

    if function.is_proto:
      raise module.Error('Attempting to call prototype %s' % function)

    context.EnterFunction(function)
    for i, typ in enumerate(function.type.argtypes):
      context.SetArgValue(typ, i, values[i])

  def GetValues(self):
    result = []
    if self.is_indirect:
      result.append(self.callee)
    result.extend(self.args)
    return result


@extend(module.RetInstruction)
class RetInstruction(object):
  def Execute(self, context):
    if self.opval:
      value = self.opval.GetValue(context)
      context.ExitFunction()
      call_inst = context.location.inst
      context.SetValue(call_inst.type, call_inst.value_idx, value)
    else:
      context.ExitFunction()
    context.location.NextInstruction()

  def GetValues(self):
    if self.opval:
      return [self.opval]
    return []


@extend(module.VSelectInstruction)
class VSelectInstruction(object):
  def Execute(self, context):
    value = self.cond.GetValue(context)
    if value:
      context.SetValue(self.type, self.value_idx,
                       self.trueval.GetValue(context))
    else:
      context.SetValue(self.type, self.value_idx,
                       self.falseval.GetValue(context))
    context.location.NextInstruction()

  def GetValues(self):
    return [self.cond, self.trueval, self.falseval]


# Built-in functions (IRT) #

@log_fn
def nacl_irt_query(context, name_p, table_p, table_size):
  name_mem, name_p = context.GetMemoryFromAddress(name_p)
  name = memory.ReadCString(name_mem, name_p)

  print '>>> nacl_irt_query(%r)' % name

  table_mem, table_p = context.GetMemoryFromAddress(table_p)

  def BuiltinFunctionToId(fn):
    try:
      index = builtin_functions.index(fn)
    except ValueError:
      raise module.Error('Function not in builtin_functions')
    return FN_HIGH_BIT | index

  def WriteTable(iface):
    writer = memory.MemoryWriter(table_mem, table_p)
    count = min(table_size / 4, len(iface))
    for i in range(count):
      fn_id = BuiltinFunctionToId(iface[i])
      writer.WriteU32(fn_id)
    return count * 4

  iface = nacl_irt_query_map.get(name)
  if iface:
    return WriteTable(iface)
  else:
    raise NotImplementedError()
  return 0

EBADF = 9
EAGAIN = 11
EINVAL = 22
ENOSYS = 38

# nacl-irt-basic-0.1 interface #
@log_fn
def nacl_irt_basic_exit(context, status):
  sys.exit(status)

@log_fn
def nacl_irt_basic_gettod(context, timeval_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_basic_clock(context, ticks_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_basic_nanosleep(context, req_p, rem_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_basic_sched_yield(context):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_basic_sysconf(context, name, value_p):
  # TODO(binji): What are appropriate values for these?
  mem, value_p = context.GetMemoryFromAddress(value_p)
  if name == 0:  # _SC_SENDMSG_MAX_SIZE
    mem.WriteU32(value_p, 4096)
    return 0
  elif name == 1:  #_SC_NPROCESSORS_ONLN
    mem.WriteU32(value_p, 1)
    return 0
  elif name == 2:  # _SC_PAGESIZE
    mem.WriteU32(value_p, 4096)
    return 0
  return EINVAL

# nacl-irt-fdio-0.1 interface #
@log_fn
def nacl_irt_fdio_close(context, fd):
  if fd not in (0, 1, 2):  # stdout, stderr
    return EBADF
  return 0

@log_fn
def nacl_irt_fdio_dup(context, fd, newfd_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_fdio_dup2(context, fd, newfd):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_fdio_read(context, fd, buf_p, count, nread_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_fdio_write(context, fd, buf_p, count, nwrote_p):
  if fd not in (1, 2):  # stdout, stderr
    return 9  # EBADF

  mem, buf_p = context.GetMemoryFromAddress(buf_p)
  data = memory.ReadCString(mem, buf_p)
  print 'nacl_irt_fdio_write >> %r' % data
  return 0

@log_fn
def nacl_irt_fdio_seek(context, fd, offset, whence, new_offset_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_fdio_fstat(context, fd, stat_p):
  # offset size
  # 0  8 dev_t     st_dev;
  # 8  8 ino_t     st_ino;
  # 16 4 mode_t    st_mode;
  # 20 4 nlink_t   st_nlink;
  # 24 4 uid_t     st_uid;
  # 28 4 gid_t     st_gid;
  # 32 8 dev_t     st_rdev;
  # 40 8 off_t     st_size;
  # 48 4 blksize_t st_blksize;
  # 52 4 blkcnt_t  st_blocks;
  # 56 8 time_t    st_atime;
  # 64 8 int64_t   st_atimensec;
  # 72 8 time_t    st_mtime;
  # 80 8 int64_t   st_mtimensec;
  # 88 8 time_t    st_ctime;
  # 96 8 int64_t   st_ctimensec;
  # 104 total
  if fd != 1:
    return EINVAL
  mem, stat_p = context.GetMemoryFromAddress(stat_p)
  mem.WriteU64(stat_p + 0, 11)      # st_dev
  mem.WriteU64(stat_p + 8, 16)      # st_ino
  mem.WriteU32(stat_p + 16, 20620)  # st_mode
  mem.WriteU32(stat_p + 20, 1)      # st_nlink
  mem.WriteU32(stat_p + 24, 1)      # st_uid
  mem.WriteU32(stat_p + 28, 1)      # st_gid
  mem.WriteU64(stat_p + 32, 34829)  # st_rdev
  mem.WriteU64(stat_p + 40, 0)      # st_size
  mem.WriteU32(stat_p + 48, 1024)   # st_blksize
  mem.WriteU32(stat_p + 52, 0)      # st_blocks
  mem.WriteU64(stat_p + 56, 0)      # st_atime
  mem.WriteU64(stat_p + 64, 0)      # st_atimensec
  mem.WriteU64(stat_p + 72, 0)      # st_mtime
  mem.WriteU64(stat_p + 80, 0)      # st_mtimensec
  mem.WriteU64(stat_p + 88, 0)      # st_ctime
  mem.WriteU64(stat_p + 96, 0)      # st_ctimensec
  return 0

@log_fn
def nacl_irt_fdio_getdents(context, fd, dirent_p, count, nread_p):
  raise NotImplementedError()
  return ENOSYS

# nacl-irt-memory-0.3 interface #
@log_fn
def nacl_irt_memory_mmap(context, addr_pp, len_, prot, flags, fd, off):
  if (flags & 0x20) != 0x20:  # MAP_ANONYMOUS
    return EINVAL

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
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_memory_mprotect(context, addr, len_, prot):
  raise NotImplementedError()
  return ENOSYS

# nacl-irt-tls-0.1 interface #
@log_fn
def nacl_irt_tls_init(context, thread_ptr_p):
  context.tls_p = thread_ptr_p
  return 0

@log_fn
def nacl_irt_tls_get(context):
  return context.tls_p

@log_fn
def nacl_irt_thread_thread_create(context, start_func_p, stack_p, thread_ptr_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_thread_thread_exit(context, stack_flag_p):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_thread_thread_nice(context, nice):
  raise NotImplementedError()
  return ENOSYS

@log_fn
def nacl_irt_futex_futex_wait_abs(context, addr_p, value, abstime_p):
  raise NotImplementedError()
  # (Doc From irt.h)
  # If |*addr| still contains |value|, futex_wait_abs() waits to be
  # woken up by a futex_wake(addr,...) call from another thread;
  # otherwise, it immediately returns EAGAIN (which is the same as
  # EWOULDBLOCK).  If woken by another thread, it returns 0.  If
  # |abstime| is non-NULL and the time specified by |*abstime|
  # passes, this returns ETIMEDOUT.
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  cur_value = mem.ReadU32(value)
  if value == cur_value:
    # Pretend we are woken up by another thread
    return 0
  else:
    return EAGAIN

@log_fn
def nacl_irt_futex_futex_wake(context, addr_p, nwake, count_p):
  # (Doc From irt.h)
  # futex_wake() wakes up threads that are waiting on |addr| using
  # futex_wait().  |nwake| is the maximum number of threads that will be
  # woken up.  The number of threads that were woken is returned in
  # |*count|.
  mem, count_p = context.GetMemoryFromAddress(count_p)
  mem.WriteU32(count_p, 0)
  return 0

nacl_irt_basic_0_1 = [
  nacl_irt_basic_exit,
  nacl_irt_basic_gettod,
  nacl_irt_basic_clock,
  nacl_irt_basic_nanosleep,
  nacl_irt_basic_sched_yield,
  nacl_irt_basic_sysconf,
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

nacl_irt_thread_0_1 = [
  nacl_irt_thread_thread_create,
  nacl_irt_thread_thread_exit,
  nacl_irt_thread_thread_nice,
]

nacl_irt_futex_0_1 = [
  nacl_irt_futex_futex_wait_abs,
  nacl_irt_futex_futex_wake,
]

nacl_irt_query_map = {
  'nacl-irt-basic-0.1': nacl_irt_basic_0_1,
  'nacl-irt-fdio-0.1': nacl_irt_fdio_0_1,
  'nacl-irt-memory-0.3': nacl_irt_memory_0_3,
  'nacl-irt-tls-0.1': nacl_irt_tls_0_1,
  'nacl-irt-thread-0.1': nacl_irt_thread_0_1,
  'nacl-irt-futex-0.1': nacl_irt_futex_0_1,
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
AddInterface(nacl_irt_thread_0_1)
AddInterface(nacl_irt_futex_0_1)


# Intrinsics #

@log_fn
def llvm_memcpy_p0i8_p0i8_i32(context, dst_p, src_p, len_, align, isvolatile):
  dst_mem, dst_p = context.GetMemoryFromAddress(dst_p)
  src_mem, src_p = context.GetMemoryFromAddress(src_p)
  # TODO(binji): optimize
  for off in range(len_):
    value = src_mem.ReadU8(src_p + off)
    dst_mem.WriteU8(dst_p + off, value)

@log_fn
def llvm_memmove_p0i8_p0i8_i32(context, dst_p, src_p, len_, align, isvolatile):
  dst_mem, dst_p = context.GetMemoryFromAddress(dst_p)
  src_mem, src_p = context.GetMemoryFromAddress(src_p)
  # TODO(binji): optimize
  if dst_mem == src_mem and dst_p > src_p:
    # Copy backwards
    for off in reversed(range(len_)):
      value = src_mem.ReadU8(src_p + off)
      dst_mem.WriteU8(dst_p + off, value)
  else:
    # Copy forwards
    for off in range(len_):
      value = src_mem.ReadU8(src_p + off)
      dst_mem.WriteU8(dst_p + off, value)


@log_fn
def llvm_memset_p0i8_i32(context, dst_p, value, len_, align, isvolatile):
  dst_mem, dst_p = context.GetMemoryFromAddress(dst_p)
  for off in range(len_):
    dst_mem.WriteU8(dst_p + off, value)

@log_fn
def llvm_nacl_atomic_load_i32(context, addr_p, flags):
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  return mem.ReadU32(addr_p)

@log_fn
def llvm_nacl_atomic_rmw_i32(context, op, addr_p, value, memory_order):
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  # Exchange is a special case; we don't write the same value we return.
  if op == 6:  # Exchange
    result = mem.ReadU32(addr_p)
    mem.WriteU32(addr_p, value)
    return result

  if op == 1:  # Add
    result = mem.ReadU32(addr_p) + value
  elif op == 2:  # Sub
    result = mem.ReadU32(addr_p) - value
  elif op == 3:  # And
    result = mem.ReadU32(addr_p) & value
  elif op == 4:  # Or
    result = mem.ReadU32(addr_p) | value
  elif op == 5:  # Xor
    result = mem.ReadU32(addr_p) ^ value
  else:
    raise module.Error('Invalid rmw op: %d' % op)

  result = IntegerType(32).CastValue(result)
  mem.WriteU32(addr_p, result)
  return result

@log_fn
def llvm_nacl_atomic_store_i32(context, value, addr_p, flags):
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  return mem.WriteU32(addr_p, value)

@log_fn
def llvm_nacl_atomic_cmpxchg_i32(context, addr_p, expected, desired,
                                 memory_order_success, memory_order_failure):
  mem, addr_p = context.GetMemoryFromAddress(addr_p)
  result = mem.ReadU32(addr_p)
  if result == expected:
    mem.WriteU32(addr_p, desired)
  return result

@log_fn
def llvm_nacl_read_tp(context):
  return context.tls_p

intrinsics = {
  'llvm.memcpy.p0i8.p0i8.i32': llvm_memcpy_p0i8_p0i8_i32,
  'llvm.memmove.p0i8.p0i8.i32': llvm_memmove_p0i8_p0i8_i32,
  'llvm.memset.p0i8.i32': llvm_memset_p0i8_i32,
  'llvm.nacl.atomic.load.i32': llvm_nacl_atomic_load_i32,
  'llvm.nacl.atomic.rmw.i32': llvm_nacl_atomic_rmw_i32,
  'llvm.nacl.atomic.store.i32': llvm_nacl_atomic_store_i32,
  'llvm.nacl.atomic.cmpxchg.i32': llvm_nacl_atomic_cmpxchg_i32,
  'llvm.nacl.read.tp': llvm_nacl_read_tp,
}

###############################################################################

class NullPointerError(Exception):
  pass


class CheckedMemory(memory.MemoryBuffer):
  def __init__(self, name, num_bytes):
    memory.MemoryBuffer.__init__(self, num_bytes)
    self.name = name
    self.constants_offset = None

  def Read(self, typ, offset):
    if offset == 0:
      raise NullPointerError('Reading from NULL in %r' % self)
    value = memory.MemoryBuffer.Read(self, typ, offset)
    print '!!! Read %s %s => %s' % (self.name, offset, value)
    return value

  def Write(self, typ, offset, value):
    if offset == 0:
      raise NullPointerError('Writing to NULL in %r' % self)
    if self.constants_offset and offset >= self.constants_offset:
      raise module.Error('Writing to constant value in %r' % self)
    print '!!! Write %s => %s %d' % (value, self.name, offset)
    memory.MemoryBuffer.Write(self, typ, offset, value)


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
    self.memory = CheckedMemory('STACK', stack_size)
    self.frames = []
    self.top = 4  # Skip NULL address

  def EnterFunction(self, location, values):
    print '+++ Entering function. new stack depth = %d' % len(self.frames)
    self.frames.append(CallFrame(location, values, self.top))

  def ExitFunction(self):
    frame = self.frames[-1]
    self.frames.pop()
    print '--- Exiting function. new stack depth = %d' % len(self.frames)
    self.top = frame.top
    return frame.location, frame.values

  def Alloca(self, size, alignment):
    self.top = memory.Align(self.top, alignment)
    result = self.top
    self.top += size
    if self.top > self.memory.num_bytes:
      self.memory.Resize(self.top)

    return ADDRESS_SOURCE_STACK | result


class CallFrame(object):
  def __init__(self, location, values, top):
    self.location = copy.copy(location)
    self.values = values  # reference, don't copy. These won't be changed.
    self.top = top


class GlobalMemory(object):
  def __init__(self, mod, argv=None, envp=None):
    self.memory = CheckedMemory('GLOBAL', mod.GetMemSize(argv, envp))
    writer = memory.MemoryWriter(self.memory)
    constants_offset, _ = mod.InitializeMemory(writer, argv, envp)
    self.memory.constants_offset = constants_offset


class Heap(object):
  def __init__(self, init_size):
    self.memory = CheckedMemory('HEAP', init_size)

  def Resize(self, new_size):
    self.memory.Resize(new_size)


class Context(object):
  def __init__(self, mod, stack_size, argv=None, envp=None):
    self.module = mod
    self.stack = Stack(stack_size)
    self.heap = Heap(4)  # Skip the NULL address
    self.global_memory = GlobalMemory(mod, argv, envp)
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

  def SetValue(self, typ, idx, value):
    offset = self.location.function.value_idx_offset
    self.values[idx - offset] = typ.CastValue(value)

  def SetArgValue(self, typ, idx, value):
    assert 0 <= idx < len(self.location.function.type.argtypes)
    self.values[idx] = typ.CastValue(value)

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


def Run(mod, stack_size, argv=None, envp=None):
  context = Context(mod, stack_size, argv, envp)
  # First arg is the address of the init structure. We always initialize it to
  # 4.
  context.SetArgValue(IntegerType(32), 0, 4)
  last_bb_idx = None
  last_function = None
  while True:
    if context.location.function != last_function:
      print '* Function %s' % context.location.function
      last_function = context.location.function

    if context.location.bb_idx != last_bb_idx:
      print '** Block %s' % context.location.bb_idx
      last_bb_idx = context.location.bb_idx
    inst = context.location.inst

    print '  ', inst

    for value in inst.GetValues():
      try:
        print '    %s = %s' % (value, value.GetValue(context))
      except:
        print '    %s = Invalid' % value

    function_before = context.location.function
    inst.Execute(context)
    function_after = context.location.function
    function_changed = function_before != function_after

    if not function_changed and inst.HasValue():
      print '    %%%s = %s' % (inst.value_idx, context.GetValue(inst.value_idx))


def main(args):
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  if not args:
    parser.error('Expected file')

  m = module.Read(open(args[0]))
  Run(m, 128, args[1:])

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
