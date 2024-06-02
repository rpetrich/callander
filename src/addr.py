import re
import subprocess
import xml.etree.ElementTree as ET

class AddrOffsetCommand(gdb.Command):
    """Get file offsets for mapped addresses"""

    def __init__(self):
        super(AddrOffsetCommand, self).__init__("addroffset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        pid = gdb.selected_inferior().pid
        maps_path = "/proc/%d/maps" % pid

        maps_lines = open(maps_path).read().split("\n")

        addr = None
        if len(arg) != 0 and arg[0] == '0':
            addr = int(arg, 16)

        last_path = ""
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
            if addr is None:
                if path == last_path:
                    continue
                if path[0] != '[' and (arg == "" or path.find(arg) != -1):
                    print(path + " @ " + hex(memstart-int(offset, 16)))
            else:
                if memstart <= addr and addr < memend:
                    description = path + "+" + hex(addr-memstart+int(offset, 16))
                    if perms[2] != "x":
                        description = description + " (not executable)"
                    print(description)
                    return
            last_path = path
        if addr is not None:
            print("could not find offset for " + hex(addr))

AddrOffsetCommand()

class AddrOffsetFunction(gdb.Function):
    """Get file offsets for mapped addresses"""

    def __init__(self):
        super(AddrOffsetFunction, self).__init__("addroffset")

    def invoke(self, arg):

        pid = gdb.selected_inferior().pid
        maps_path = "/proc/%d/maps" % pid

        maps_lines = open(maps_path).read().split("\n")

        # addr = int(arg.format_string(format="x"), 16)
        if arg is None:
            return "missing arg"
        addr = int(str(arg), 0)

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
                    description = description + " (not executable)"
                return description
        return hex(addr) + " (not mapped)"
        # print("could not find offset for " + hex(addr))

AddrOffsetFunction()

class SyscallArgsCommand(gdb.Command):
    """Print syscall arguments in registers"""

    def __init__(self):
        super(SyscallArgsCommand, self).__init__("syscallargs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rax = str(gdb.parse_and_eval("$rax"))
        for syscall in ET.parse("/usr/share/gdb/syscalls/amd64-linux.xml").getroot():
            if syscall.get("number") == rax:
                rax = syscall.get("name", rax)
                break
        print(str(rax) + "(" + str(gdb.parse_and_eval("$rdi").format_string(format="x")) + ", " + str(gdb.parse_and_eval("$rsi").format_string(format="x")) + ", " + str(gdb.parse_and_eval("$rdx").format_string(format="x")) + ", " + str(gdb.parse_and_eval("$r10").format_string(format="x")) + ", " + str(gdb.parse_and_eval("$r8").format_string(format="x")) + ", " + str(gdb.parse_and_eval("$r9").format_string(format="x")) + ")")

SyscallArgsCommand()

