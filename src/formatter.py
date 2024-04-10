import re
import math
import os

def aarch64_name_for_reg(reg):
  if reg < 30:
    return 'r' + str(reg)
  if reg == 30:
    return 'sp'
  if reg == 31:
    return 'mem'
  return 'stack+' + str((reg - 32) * 4)

def name_for_effect(effect):
  if effect == 0:
    return "returns"
  if effect == 1:
    return "exits"
  if effect == 2:
    return "sticky-exits"
  if effect == 3:
    return "processed"
  if effect == 4:
    return "processing"
  if effect == 5:
    return "after-startup"
  if effect == 6:
    return "entrypoint"
  if effect == 7:
    return "enter-calls"
  if effect == 8:
    return "modifies-stack"
  return '1<<' + str(effect)

class BitflagPrinter:
  def __init__(self, val, converter):
    self.val = val
    self.converter = converter

  def to_string(self):
    try:
      val = int(self.val)
    except:
      val = int(self.val.format_string(raw=True, format='x'), 16)
    if val == 0:
      return "<empty>"
    regs = []
    while val != 0:
      bit = val & (~val+1)
      i = math.log(bit, 2)
      regs.append(self.converter(int(i)))
      val ^= bit
    return '|'.join(regs)

maps_lines = None

def maps_path():
  return "/proc/%s/maps" % os.getenv("INFERIOR_PID", str(gdb.selected_inferior().pid))

def try_format_address(addr):
  for line in maps_lines:
    memrange, perms, offset, devnum, size, path = (None, None, None, None, None, None)

    try:
      memrange, perms, offset, devnum, size, path = re.split("\\s+", line)
    except:
      continue

    if path == "":
      path = "[anonymous]"

    components = memrange.split("-")
    memstart = int(components[0], 16)
    memend = int(components[1], 16)

    if memstart <= addr and addr < memend:
      description = path + "+" + hex(addr-memstart+int(offset, 16))
      if perms[2] != "x":
        description = description + "~x"
      return description

def format_address(addr):
    global maps_lines
    if maps_lines is not None:
      # try cache
      result = try_format_address(addr)
      if result is not None:
        return result
    # reload cache
    maps_lines = open(maps_path()).read().split("\n")

    # and try again
    return try_format_address(addr)

class AddrPrinter:
  def __init__(self, val):
    self.val = val

  def to_string(self):
    addr = int(self.val)
    result = format_address(addr)
    if result is not None:
      return result
    return hex(addr)

def format_int(value):
  if value == 0xffffffffffffffff:
    return '-1'
  if value == 0xffffffff:
    return '-1 as u32'
  if value < 4096:
    return str(value)
  result = format_address(value)
  if result is not None:
    return result
  return hex(value)

class RegisterStatePrinter:
  def __init__(self, val):
    self.val = val

  def to_string(self):
    value = int(self.val['value'])
    max = int(self.val['max'])
    if value == max:
      return format_int(value)
    if value == 0:
      if max == 0xffffffffffffffff:
        return 'any'
      if max == 0xffffffff:
        return 'any u32'
      if max == 0x7fffffff:
        return '0-INT_MAX'
      if max == 0xffffffff:
        return 'any u32'
      if max == 0xffff:
        return 'any u32'
      if max == 0xff:
        return 'any u8'
    return format_int(value) + '-' + format_int(max)

def callander_printers(val):
  if str(val.type) == 'register_mask':
    return BitflagPrinter(val, aarch64_name_for_reg)
  if str(val.type) == 'function_effects':
    return BitflagPrinter(val, name_for_effect)
  if str(val.type) == 'ins_ptr':
    return AddrPrinter(val)
  if str(val.type) == 'struct register_state':
    return RegisterStatePrinter(val)

gdb.pretty_printers.insert(0, callander_printers)
