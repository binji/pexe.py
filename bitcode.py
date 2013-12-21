#!/usr/bin/env python
# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import struct
import sys

ENTRY_END_BLOCK = 0
ENTRY_SUBBLOCK = 1
ENTRY_DEFINE_ABBREV = 2
ENTRY_UNABBREV_RECORD = 3

ENCODING_FIXED = 1
ENCODING_VBR = 2
ENCODING_ARRAY = 3
ENCODING_CHAR6 = 4
ENCODING_BLOB = 5

BLOCKINFO_CODE_SETBID = 1
BLOCKINFO_CODE_BLOCKNAME = 2
BLOCKINFO_CODE_SETRECORDNAME = 3

CHAR6 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._'


class Error(Exception):
  pass


class BitStream(object):
  def __init__(self, data):
    self.data = data
    self.datalen = len(self.data)
    self.curword = 0
    self.curword_bits = 0
    self.bit_offset = 0

    # Pad data out to 32-bits, with an additional 32-bits (so we don't have
    # to worry about calling struct.unpack_from at the end).
    padding = 4 + ((4 - self.datalen & 3) & 3)
    self.data += '\0' * padding

  def _ReadFracBits(self, num_bits):
    assert num_bits <= self.curword_bits

    result = self.curword & ((1 << num_bits) - 1)
    self.curword >>= num_bits
    self.curword_bits -= num_bits
    self.bit_offset += num_bits
    return result

  def _FillCurWord(self):
    byte_offset = self.bit_offset >> 3
    self.curword = struct.unpack_from('<L', self.data, byte_offset)[0]
    if byte_offset + 4 < self.datalen:
      self.curword_bits = 32
    else:
      self.curword_bits = (self.datalen - byte_offset) * 8
    assert self.curword_bits <= 32

  def Read(self, num_bits):
    assert num_bits <= 32
    if num_bits <= self.curword_bits:
      return self._ReadFracBits(num_bits)

    result = self.curword
    bits_read = self.curword_bits
    bits_left = num_bits - self.curword_bits
    self.bit_offset += bits_read
    self._FillCurWord()
    result |= self._ReadFracBits(bits_left) << bits_read
    return result

  def ReadVbr(self, num_bits):
    piece = self.Read(num_bits)
    hi_mask = 1 << (num_bits - 1)
    if (piece & hi_mask) == 0:
      return piece

    lo_mask = hi_mask - 1
    result = 0
    shift = 0
    while True:
      result |= (piece & lo_mask) << shift
      if (piece & hi_mask) == 0:
        return result
      shift += num_bits - 1
      piece = self.Read(num_bits)

  def ReadBytes(self, num_bytes):
    result = []
    for _ in range(num_bytes):
      result.append(self.Read(8))
    return result

  def TellBit(self):
    return self.bit_offset

  def SeekBit(self, offset):
    # Align to 32-bits
    self.bit_offset = offset & ~31
    self._FillCurWord()

    # Offset is not aligned, read the unaligned bits.
    offset &= 31
    if offset:
      self._ReadFracBits(offset)

  def Align32(self):
    self.SeekBit((self.TellBit() + 31) & ~31)

  def AtEnd(self):
    byte_offset = self.bit_offset >> 3
    return byte_offset == self.datalen

  def __repr__(self):
    return ('<BitStream bit_offset=%d curword=0x%0x '
             'curword_bits=%d datalen=%d>' % (
        self.bit_offset, self.curword, self.curword_bits, self.datalen))


class HeaderField(object):
  def __init__(self):
    self.ftype = None
    self.id = None
    self.data = None

  def Read(self, bs):
    self.ftype = bs.Read(4)
    self.id = bs.Read(4)
    if self.id != 1:
      raise Error('Bad header id %d' % self.id)

    bs.Read(8)  # align to u16
    length = bs.Read(16)

    if self.ftype == 0:
      self.data = bs.ReadBytes(length)
    elif self.ftype == 1:
      self.data = bs.Read(32)
    else:
      raise Error('Bad ftype %d' % self.ftype)


class Header(object):
  def __init__(self):
    self.sig = None
    self.num_fields = 0
    self.num_bytes = 0
    self.fields = []

  def Read(self, bs):
    for c in 'PEXE':
      if bs.Read(8) != ord(c):
        raise Error('Bad signature')
    self.sig = 'PEXE'
    self.num_fields = bs.Read(16)
    self.num_bytes = bs.Read(16)

    for _ in range(self.num_fields):
      field = HeaderField()
      field.Read(bs)
      self.fields.append(field)


class AbbrevOp(object):
  def Read(self, bs):
    pass

  def ReadAbbrev(self, bs):
    raise NotImplementedError()


class LiteralAbbrevOp(AbbrevOp):
  def __init__(self):
    AbbrevOp.__init__(self)
    self.value = None

  def Read(self, bs):
    self.value = bs.ReadVbr(8)

  def ReadAbbrev(self, bs):
    return [self.value]


class FixedAbbrevOp(AbbrevOp):
  def __init__(self):
    AbbrevOp.__init__(self)
    self.num_bits = None

  def Read(self, bs):
    self.num_bits = bs.ReadVbr(5)

  def ReadAbbrev(self, bs):
    return [bs.Read(self.num_bits)]


class VbrAbbrevOp(AbbrevOp):
  def __init__(self):
    AbbrevOp.__init__(self)
    self.num_bits = None

  def Read(self, bs):
    self.num_bits = bs.ReadVbr(5)

  def ReadAbbrev(self, bs):
    return [bs.ReadVbr(self.num_bits)]


class ArrayAbbrevOp(AbbrevOp):
  def __init__(self):
    AbbrevOp.__init__(self)
    self.elt_op = None

  def Read(self, bs):
    self.elt_op = Abbrev.ReadAbbrevOp(bs)

  def ReadAbbrev(self, bs):
    num_elts = bs.ReadVbr(6)
    values = []
    for _ in range(num_elts):
      values.extend(self.elt_op.ReadAbbrev(bs))
    return values


class Char6AbbrevOp(AbbrevOp):
  def ReadAbbrev(self, bs):
    return CHAR6[bs.Read(6)]


class BlobAbbrevOp(AbbrevOp):
  def ReadAbbrev(self, bs):
    num_bytes = bs.Read(6)
    bs.Align32()
    # TODO(binji): empty record when trying to read past the end...
    values = []
    for _ in range(num_bytes):
      values.append(bs.Read(8))
    bs.Align32()
    return values


class Abbrev(object):
  def __init__(self):
    self.ops = []

  def Read(self, bs):
    num_ops = bs.ReadVbr(5)
    i = 0
    while i < num_ops:
      op = Abbrev.ReadAbbrevOp(bs)
      self.ops.append(op)

      # Arrays use the following op as the element op.
      if isinstance(op, ArrayAbbrevOp):
        i += 2
      else:
        i += 1

  @staticmethod
  def ReadAbbrevOp(bs):
    is_literal = bs.Read(1)
    if is_literal:
      op = LiteralAbbrevOp()
    else:
      encoding = bs.Read(3)
      if encoding == ENCODING_FIXED:
        op = FixedAbbrevOp()
      elif encoding == ENCODING_VBR:
        op = VbrAbbrevOp()
      elif encoding == ENCODING_ARRAY:
        op = ArrayAbbrevOp()
      elif encoding == ENCODING_CHAR6:
        op = Char6AbbrevOp()
      elif encoding == ENCODING_BLOB:
        op = BlobAbbrevOp()
      else:
        raise Error('Bad encoding %d' % encoding)
    op.Read(bs)
    return op


class BlockInfoContext(object):
  def __init__(self):
    self.cur_bid = None
    self.block_abbrevs = {}
    self.block_names = {}
    self.block_record_names = {}

  def ParseRecord(self, record):
    if record.code == BLOCKINFO_CODE_SETBID:
      self.cur_bid = record.values[0]
    elif record.code == BLOCKINFO_CODE_BLOCKNAME:
      name = ''.join(chr(x) for x in record.values)
      self.block_names[self.cur_bid] = name
    elif record.code == BLOCKINFO_CODE_SETRECORDNAME:
      id_ = record[0]
      name = ''.join(chr(x) for x in record.values[1:])
      self.block_record_names.setdefault(self.cur_bid, []).append((id_, name))

  def AppendAbbrev(self, abbrev):
    self.block_abbrevs.setdefault(self.cur_bid, []).append(abbrev)

  def GetBlockAbbrevs(self, block_id):
    return self.block_abbrevs.get(block_id, [])


class Chunk(object):
  pass


class Record(Chunk):
  def __init__(self):
    self.code = None
    self.values = []

  def Read(self, bs, abbrev_id, abbrevs):
    if abbrev_id == ENTRY_UNABBREV_RECORD:
      self.code = bs.ReadVbr(6)
      num_elts = bs.ReadVbr(6)
      for _ in range(num_elts):
        self.values.append(bs.ReadVbr(6))
    else:
      abbrev = abbrevs[abbrev_id - 4]  # 4 => skip abbrev defaults
      for op in abbrev.ops:
        self.values.extend(op.ReadAbbrev(bs))
      self.code = self.values[0]
      self.values = self.values[1:]


class Block(Chunk):
  def __init__(self):
    self._id = None
    self.chunks = []

  def Read(self, bs, context):
    self._id = bs.ReadVbr(8)
    codelen = bs.ReadVbr(4)
    bs.Align32()
    _ = bs.Read(32)  # num_words

    # Add abbreviations for this block id.
    abbrevs = []
    abbrevs.extend(context.GetBlockAbbrevs(self._id))

    is_block_info = self._id == 0

    while not bs.AtEnd():
      entry = bs.Read(codelen)
      if entry == ENTRY_END_BLOCK:
        bs.Align32()
        return
      elif entry == ENTRY_SUBBLOCK:
        block = Block()
        block.Read(bs, context)
        self.chunks.append(block)
      elif entry == ENTRY_DEFINE_ABBREV:
        abbrev = Abbrev()
        abbrev.Read(bs)
        abbrevs.append(abbrev)
        if is_block_info:
          context.AppendAbbrev(abbrev)
      else:
        # Abbrev or UNABBREV_RECORD
        record = Record()
        record.Read(bs, entry, abbrevs)
        self.chunks.append(record)
        if is_block_info:
          context.ParseRecord(record)

  def GetBlocks(self):
    return [x for x in self.chunks if isinstance(x, Block)]

  def GetRecords(self):
    return [x for x in self.chunks if isinstance(x, Record)]


class BitCode(object):
  def __init__(self):
    self.header = Header()
    self.blocks = []

  def Read(self, bs):
    context = BlockInfoContext()
    self.header.Read(bs)
    while not bs.AtEnd():
      entry = bs.Read(2)
      if entry != ENTRY_SUBBLOCK:
        raise Error('Expected subblock at top-level, not %d' % entry)
      block = Block()
      block.Read(bs, context)
      self.blocks.append(block)


def Read(f):
  return ReadString(f.read())


def ReadString(s):
  bs = BitStream(s)
  bc = BitCode()
  bc.Read(bs)
  return bc


def _PrintBitcode(bc):
  import json
  class Encoder(json.JSONEncoder):
    def default(self, o):
      d = o.__dict__
      if len(o.__class__.__mro__) > 2:
        d = dict(d)
        d.update(_type=o.__class__.__name__)
      return d
  print json.dumps(bc, cls=Encoder, indent=2, sort_keys=True)


def main(args):
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  if not args:
    parser.error('Expected file')

  bc = Read(open(args[0]))
  #_PrintBitcode(bc)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
