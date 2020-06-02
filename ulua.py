#!/usr/bin/env python3

# ulua.py
# Copyright (C) 2020  Daniel Santos

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import struct
import array
import sys

LUA_OPCODE_TYPES = [
    "ABC",  "ABx", "ABC",  "ABC",
    "ABC",  "ABx", "ABC",  "ABx",
    "ABC",  "ABC", "ABC",  "ABC",
    "ABC",  "ABC", "ABC",  "ABC",
    "ABC",  "ABC", "ABC",  "ABC",
    "ABC",  "ABC", "AsBx", "ABC",
    "ABC",  "ABC", "ABC",  "ABC",
    "ABC",  "ABC", "ABC",  "AsBx",
    "AsBx", "ABC", "ABC", "ABC",
    "ABx",  "ABC"
]

LUA_OPCODE_NAMES = [
    "MOVE",
    "LOADK",
    "LOADBOOL",
    "LOADNIL",
    "GETUPVAL",
    "GETGLOBAL",
    "GETTABLE",
    "SETGLOBAL",
    "SETUPVAL",
    "SETTABLE",
    "NEWTABLE",
    "SELF",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "UNM",
    "NOT",
    "LEN",
    "CONCAT",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "FORLOOP",
    "FORPREP",
    "TFORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
]

VARARG_HASARG = 1
VARARG_ISVARARG = 2
VARARG_NEEDSARG = 4

BIG_ENDIAN = 0
LITTLE_ENDIAN = 1

# at [p]osition to k


def get_bits(num, p, k):
    # convert number into binary first
    binary = format(num, 'b')

    # # remove first two characters
    # binary = binary[2:]

    # fill in missing bits
    for _ in range(32 - len(binary)):
        binary = '0' + binary

    p -= 1
    k -= 1
    #end = len(binary) - p + 1
    #start = len(binary) - k + 1

    # extract k  bit sub-string
    kBitSubStr = (binary[::-1])[p: k+1][::-1]

    # convert extracted sub-string into decimal again
    return (int(kBitSubStr, 2))


class LuaByteCodeParser:
    def __init__(self):
        self.index = 0

    def get_byte(self, chunk):
        b = chunk.get_byte(self.index)
        self.index += 1
        return b

    def get_int32(self, chunk):
        i = chunk.get_int32(self.index)
        self.index += chunk.header.int_size
        return i

    def get_int(self, chunk):
        i = chunk.get_int(self.index)
        self.index += chunk.header.int_size
        return i

    def get_size_t(self, chunk):
        s = chunk.get_size_t(self.index)
        self.index += chunk.header.size_t_size
        return s

    def get_double(self, chunk):
        f = chunk.get_double(self.index)
        self.index += 8
        return f

    def get_string(self, chunk):
        size, s = chunk.get_string(self.index)
        self.index += chunk.header.size_t_size
        self.index += size
        return s

    def decode_chunk(self, chunk, main=False, opcode_map=None):
        fb = Lua51BinaryChunkFunctionBlock()

        if(main):
            fb.source_name = self.get_string(chunk)
            if (fb.source_name):
                fb.source_name = fb.source_name[1:-1]
        else:
            fb.source_name = self.get_size_t(chunk)

        fb.line_defined = self.get_int(chunk)
        fb.last_line_defined = self.get_int(chunk)
        fb.number_of_upvalues = self.get_byte(chunk)
        fb.number_of_parameters = self.get_byte(chunk)
        varg = self.get_byte(chunk)
        fb.has_arg = varg & VARARG_HASARG > 0
        fb.is_vararg = varg & VARARG_ISVARARG > 0
        fb.needs_arg = varg & VARARG_NEEDSARG > 0
        fb.max_stack_size = self.get_byte(chunk)

        # parse instructions
        num = self.get_int(chunk)
        for _ in range(num):
            instruction = {
                # opcode = opcode number;
                # type   = [ABC, ABx, AsBx]
                # A, B, C, Bx, or sBx depending on type
            }

            data = self.get_int32(chunk)
            opcode = get_bits(data, 1, 6)
            if opcode_map:
                opcode = opcode_map[opcode]
                index = self.index - chunk.header.int_size
                chunk.bytecode_raw[index:self.index] = ((data & 0xFFFFFFC0) ^ opcode).to_bytes(
                    chunk.header.int_size, byteorder='big' if chunk.header.endianness == BIG_ENDIAN else 'little')
            tp = LUA_OPCODE_TYPES[opcode]

            instruction['OPCODE'] = opcode
            instruction['TYPE'] = tp
            instruction['A'] = get_bits(data, 7, 14)

            if instruction['TYPE'] == "ABC":
                instruction['B'] = get_bits(data, 24, 32)
                instruction['C'] = get_bits(data, 15, 23)
            elif instruction['TYPE'] == "ABx":
                instruction['Bx'] = get_bits(data, 15, 32)
            elif instruction['TYPE'] == "AsBx":
                instruction['sBx'] = get_bits(data, 15, 32) - 131071

            fb.instructions.append(instruction)

        # get constants
        num = self.get_int(chunk)

        for _ in range(num):
            constant = {
                # type = constant type;
                # data = constant data;
            }
            constant['TYPE'] = self.get_byte(chunk)

            if constant['TYPE'] == 1:
                constant['DATA'] = (self.get_byte(chunk) != 0)
            elif constant['TYPE'] == 0:
                constant['DATA'] = None
            elif constant['TYPE'] == 3:
                constant['DATA'] = self.get_double(chunk)
            elif constant['TYPE'] == 4:
                constant['DATA'] = self.get_string(chunk)[:-1]
            else:
                constant['DATA'] = self.get_int(chunk)

            fb.constants.append(constant)

        # parse protos
        num = self.get_int(chunk)
        for _ in range(num):
            fb.protos.append(self.decode_chunk(
                chunk, main=False, opcode_map=opcode_map))

        # debug stuff
        # line numbers
        num = self.get_int(chunk)
        for _ in range(num):
            self.get_int32(chunk)

        # locals
        num = self.get_int(chunk)
        for _ in range(num):
            local_name = self.get_string(chunk)[:-1]
            local_spc = self.get_int32(chunk)  # local start PC
            local_epc = self.get_int32(chunk)  # local end   PC
            fb.locals.append((local_name, local_spc, local_epc))

        # upvalues
        num = self.get_int(chunk)
        for _ in range(num):
            self.get_string(chunk)  # upvalue name

        return fb

    def parse(self, bytecode, opcode_map=None):
        chunk = Lua51BinaryChunk(bytecode)
        self.index = 4 # Skip header signature: ESC, “Lua” or 0x1B4C7561
        chunk.header.verion = self.get_byte(chunk)
        chunk.header.format = self.get_byte(chunk)
        chunk.header.endianness = self.get_byte(chunk)
        chunk.header.int_size = self.get_byte(chunk)
        chunk.header.size_t_size = self.get_byte(chunk)
        chunk.header.instruction_size = self.get_byte(chunk)
        chunk.header.lua_number_size = self.get_byte(chunk)
        chunk.header.integral_flag = self.get_byte(chunk)
        chunk.top_function_block = self.decode_chunk(
            chunk, main=True, opcode_map=opcode_map)
        return chunk


class Lua51BinaryChunkHeader:
    def __init__(self):
        self.verion = 51
        self.format = 0
        self.endianness = 1
        self.int_size = 4
        self.size_t_size = 4
        self.instruction_size = 4
        self.lua_number_size = 8
        self.integral_flag = 0

    def __str__(self):
        return str(
            {
                "VM_VERSION": hex(self.verion),
                "BIG_ENDIAN": self.endianness == BIG_ENDIAN,
                "INT_SIZE": self.int_size,
                "SIZE_T": self.size_t_size,
                "INSTRUCTION SIZE": self.instruction_size,
                "L_NUMBER SIZE": self.lua_number_size,
                "INTEGRAL FLAG": self.integral_flag
            }
        )


class Lua51BinaryChunkFunctionBlock:
    def __init__(self):
        self.source_name = ""
        self.line_defined = 0
        self.last_line_defined = 0
        self.number_of_upvalues = 0
        self.number_of_parameters = 0

        self.has_arg = False
        self.is_vararg = False
        self.needs_arg = False

        self.max_stack_size = 0

        self.instructions = []
        self.constants = []
        self.protos = []
        self.source_line_positions = []
        self.locals = []
        self.upvalues = []


class Lua51BinaryChunk:
    def __init__(self, bytecode):
        self.header = Lua51BinaryChunkHeader()
        self.top_function_block = Lua51BinaryChunkFunctionBlock()
        self.bytecode = list(map(int, bytecode))
        self.bytecode_raw = list(bytecode)

    def dump(self, filename="luac.py.out"):
        with open(filename, "bw+") as f:
            f.write(bytes(self.bytecode_raw))

    def get_byte(self, index):
        b = self.bytecode[index]
        return b

    def get_int32(self, index):
        i = 0
        if (self.header.endianness == BIG_ENDIAN):
            i = int.from_bytes(
                self.bytecode[index:index+4], byteorder='big', signed=False)
        else:
            i = int.from_bytes(
                self.bytecode[index:index+4], byteorder='little', signed=False)
        return i

    def get_int(self, index):
        i = 0
        if (self.header.endianness == BIG_ENDIAN):
            i = int.from_bytes(
                self.bytecode[index:index+self.header.int_size], byteorder='big', signed=False)
        else:
            i = int.from_bytes(
                self.bytecode[index:index+self.header.int_size], byteorder='little', signed=False)
        return i

    def get_size_t(self, index):
        s = ''
        if (self.header.endianness == BIG_ENDIAN):
            s = int.from_bytes(
                self.bytecode[index:index+self.header.size_t_size], byteorder='big', signed=False)
        else:
            s = int.from_bytes(
                self.bytecode[index:index+self.header.size_t_size], byteorder='little', signed=False)
        return s

    def get_double(self, index):
        if (self.header.endianness == BIG_ENDIAN):
            f = struct.unpack('>d', bytearray(self.bytecode[index:index+8]))
        else:
            f = struct.unpack('<d', bytearray(self.bytecode[index:index+8]))
        return f[0]

    def get_string(self, index):
        size = self.get_size_t(index)
        if (size == 0):
            return (0, "")
        index += self.header.size_t_size
        s = "".join(chr(x) for x in self.bytecode[index:index+size])
        return (size, s)

    @staticmethod
    def Match(chunkA, chunkB):
        try:
            assert len(chunkA.top_function_block.instructions) == len(
                chunkB.top_function_block.instructions)
            assert len(chunkA.top_function_block.constants) == len(
                chunkB.top_function_block.constants)
            for i, proto in enumerate(chunkA.top_function_block.protos):
                assert len(proto.instructions) == len(
                    chunkB.top_function_block.protos[i].instructions)
                assert len(proto.constants) == len(
                    chunkB.top_function_block.protos[i].constants)
            return True
        except AssertionError:
            return False


if __name__ == "__main__":
    import argparse
    import os
    import glob
    import sys
    import logging

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stdOutHandler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(stdOutHandler)

    parser = argparse.ArgumentParser(description='Unscramble lua opcodes')
    parser.add_argument('-r', '--ref', help='reference files dir')
    parser.add_argument('-s', '--sample', help='sample files dir')
    parser.add_argument('-f', '--file', help='scrambled file')
    parser.add_argument(
        '-o', '--output', help='resulting unscrambled file output path', default='./ulua.out')

    args = parser.parse_args()

    lc = LuaByteCodeParser()

    ref_chunks = {}
    logger.info("Processing reference files")
    for filepath in glob.glob(args.ref.rstrip('/') + "/*.lua"):
        logger.info("Processing file: {}".format(filepath))
        with open(filepath, 'rb') as f:
            bytecode = f.read()
            ref_chunk = lc.parse(bytecode)
            ref_chunks[os.path.basename(filepath)] = ref_chunk

    sample_chunks = {}
    logger.info("Processing sample files")
    for filepath in glob.glob(args.sample.rstrip('/') + "/*.lua"):
        logger.info("Processing file: {}".format(filepath))
        sample_chunk = None
        with open(filepath, 'rb') as f:
            bytecode = f.read()
            sample_chunk = lc.parse(bytecode)
            sample_chunks[os.path.basename(filepath)] = sample_chunk

    opcode_map = {}
    for path, ref_chunk in ref_chunks.items():
        sample_chunk = sample_chunks.get(path, None)
        if not sample_chunk:
            continue
        if Lua51BinaryChunk.Match(ref_chunk, sample_chunk):
            for i, instruction in enumerate(ref_chunk.top_function_block.instructions):
                opcode_map[sample_chunk.top_function_block.instructions[i]
                           ['OPCODE']] = instruction['OPCODE']

            for i, proto in enumerate(ref_chunk.top_function_block.protos):
                for j, instruction in enumerate(proto.instructions):
                    opcode_map[sample_chunk.top_function_block.protos[i].instructions[j]
                               ['OPCODE']] = instruction['OPCODE']
        else:
            logger.warn("{} does not match its reference file".format(path))

    logger.info("{} opcodes mapped".format(len(opcode_map)))
    for k, v in opcode_map.items():
        logger.debug("{}: {}".format(LUA_OPCODE_NAMES[k], LUA_OPCODE_NAMES[v]))

    logger.info("Patching file {} ...".format(args.file))
    with open(args.file, 'rb') as f:
        bytecode = f.read()
        chunk = lc.parse(bytecode, opcode_map=opcode_map)
        chunk.dump(args.output)
    logger.info("Patch complete!")
    logger.info("Patched file is availble at {}".format(args.output))
