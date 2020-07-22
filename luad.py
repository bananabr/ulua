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

lua_opcode_types = [
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

lua_opcode_names = [
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

SAMPLE_OPCODE_MAP = {
    "TESTSET": "MOVE",
    "SETUPVAL": "LOADK",
    "SETTABLE": "LOADBOOL",
    "SETGLOBAL": "LOADNIL",
    "NEWTABLE": "GETUPVAL",
    "LOADK": "GETGLOBAL",
    "MOVE": "GETTABLE",
    "LOADBOOL": "SETGLOBAL",
    "LOADNIL": "SETUPVAL",
    "GETUPVAL": "SETTABLE",
    "GETGLOBAL": "NEWTABLE",
    "GETTABLE": "SELF",
    "POW": "ADD",
    "MOD": "SUB",
    "DIV": "MUL",
    "MUL": "DIV",
    "UNM": "MOD",
    0: "POW", # NOT || LEN
    1: "UNM", # NOT || LEN
    "CONCAT": "NOT",
    "JMP": "LEN",
    "EQ": "CONCAT",
    "LT": "JMP",
    "SUB": "EQ",
    "SELF": "LT",
    "ADD": "LE",
    "LE": "TEST",
    "TEST": "TESTSET",
    "SETLIST": "CALL",
    "CLOSURE": "TAILCALL",
    "CLOSE": "RETURN",
    "CALL": "FORLOOP",
    "TAILCALL": "FORPREP",
    "RETURN": "TFORLOOP",
    "FORLOOP": "SETLIST",
    "FORPREP": "CLOSE",
    "TFORLOOP": "CLOSURE",
    "VARARG": "VARARG"
}

OPCODE2INDEX = {
    "MOVE": 0,
    "LOADK": 1,
    "LOADBOOL": 2,
    "LOADNIL": 3,
    "GETUPVAL": 4,
    "GETGLOBAL": 5,
    "GETTABLE": 6,
    "SETGLOBAL": 7,
    "SETUPVAL": 8,
    "SETTABLE": 9,
    "NEWTABLE": 10,
    "SELF": 11,
    "ADD": 12,
    "SUB": 13,
    "MUL": 14,
    "DIV": 15,
    "MOD": 16,
    "POW": 17,
    "UNM": 18,
    "NOT": 19,
    "LEN": 20,
    "CONCAT": 21,
    "JMP": 22,
    "EQ": 23,
    "LT": 24,
    "LE": 25,
    "TEST": 26,
    "TESTSET": 27,
    "CALL": 28,
    "TAILCALL": 29,
    "RETURN": 30,
    "FORLOOP": 31,
    "FORPREP": 32,
    "TFORLOOP": 33,
    "SETLIST": 34,
    "CLOSE": 35,
    "CLOSURE": 36,
    "VARARG": 37
}

VARARG_HASARG = 1
VARARG_ISVARARG = 2
VARARG_NEEDSARG = 4

# at [p]osition to k
def get_bits(num, p, k):
    # convert number into binary first 
    binary = format(num,'b')

    # # remove first two characters 
    # binary = binary[2:] 

    # fill in missing bits
    for i in range(32 - len(binary)):
        binary = '0' + binary

    p -= 1
    k -= 1
    #end = len(binary) - p + 1
    #start = len(binary) - k + 1

    # extract k  bit sub-string 
    kBitSubStr = (binary[::-1])[p : k+1][::-1] 

    # convert extracted sub-string into decimal again 
    return (int(kBitSubStr,2))

class LuaCompiler:
    def __init__(self, bytecode):
        self.luac = "luac5.1"
        self.o_flag = "-o"
        self.temp_out = "out.luac"
        self.chunks = []
        self.chunk = {}
        self.index = 0
        self.bytecode_raw = list(bytecode)
        self.bytecode = list(map(int, bytecode))

    def dump(self, filename="luac.py.out"):
        with open(filename,"bw+") as f:
            f.write(bytes(self.bytecode_raw))

    @staticmethod
    def dis_chunk(chunk):
        print("==== [[" + str(chunk['NAME']) + "]] ====\n")
        for z in chunk['PROTOTYPES']:
            print("** decoding proto\n")
            LuaCompiler.dis_chunk(chunk['PROTOTYPES'][z])
        
        print("\n==== [[" + str(chunk['NAME']) + "'s constants]] ====\n")
        for z in chunk['CONSTANTS']:
            i = chunk['CONSTANTS'][z]
            print(str(z) + ": " + str(i['DATA']))

        print("\n==== [[" + str(chunk['NAME']) + "'s dissassembly]] ====\n")

        # registers = {}
        # variables = {}
        for z in chunk['INSTRUCTIONS']:
            i = chunk['INSTRUCTIONS'][z]
            ip = z+1
            # if i['OPCODE'] == 30:
            #     print('return')
            # elif i['OPCODE'] == 1: # LOADK
            #     value = chunk['CONSTANTS'][i['Bx']]['DATA']
            #     registers[i['A']] = value
            #     local = chunk['LOCALS'].get(i['A'], None)
            #     if local and ip >= local[1] and ip <= local[2]:
            #         print("local {} = {}".format(local[0],value))
            #     else:
            #         print("reg{} = {}".format(i['A'],value))
            # elif i['OPCODE'] == 7: # SETGLOBAL
            #     var = chunk['CONSTANTS'][i['Bx']]['DATA']
            #     value = registers[i['A']]
            #     variables[var] = value
            #     print("{} = {}".format(var,value))
            # el
            if (i['TYPE'] == "ABC"):
                print(lua_opcode_names[i['OPCODE']], i['A'], i['B'], i['C'])
            elif (i['TYPE'] == "ABx"):
                if (i['OPCODE'] == 1 or i['OPCODE'] == 5):
                    print(lua_opcode_names[i['OPCODE']], i['A'], -i['Bx']-1, chunk['CONSTANTS'][i['Bx']]['DATA'])
                else:
                    print(lua_opcode_names[i['OPCODE']], i['A'], -i['Bx']-1)
            elif (i['TYPE'] == "AsBx"):
                print("AsBx", lua_opcode_names[i['OPCODE']], i['A'], i['sBx'])

    def get_byte(self):
        b = self.bytecode[self.index]
        self.index = self.index + 1
        return b

    def get_int32(self):
        i = 0
        if (self.big_endian):
            i = int.from_bytes(self.bytecode[self.index:self.index+4], byteorder='big', signed=False)
        else:
            i = int.from_bytes(self.bytecode[self.index:self.index+4], byteorder='little', signed=False)
        self.index = self.index + self.int_size
        return i

    def get_int(self):
        i = 0
        if (self.big_endian):
            i = int.from_bytes(self.bytecode[self.index:self.index+self.int_size], byteorder='big', signed=False)
        else:
            i = int.from_bytes(self.bytecode[self.index:self.index+self.int_size], byteorder='little', signed=False)
        self.index = self.index + self.int_size
        return i

    def get_size_t(self):
        s = ''
        if (self.big_endian):
            s = int.from_bytes(self.bytecode[self.index:self.index+self.size_t], byteorder='big', signed=False)
        else:
            s = int.from_bytes(self.bytecode[self.index:self.index+self.size_t], byteorder='little', signed=False)
        self.index = self.index + self.size_t
        return s

    def get_double(self):
        if self.big_endian:
            f = struct.unpack('>d', bytearray(self.bytecode[self.index:self.index+8]))
        else:
            f = struct.unpack('<d', bytearray(self.bytecode[self.index:self.index+8]))
        self.index = self.index + 8
        return f[0]

    def get_string(self, size):
        if (size == None):
            size = self.get_size_t()
            if (size == 0):
                return None
        
        s = "".join(chr(x) for x in self.bytecode[self.index:self.index+size])
        self.index = self.index + size
        return s

    def decode_chunk(self, main=False, patch=False):
        chunk = {
            'INSTRUCTIONS': {},
            'CONSTANTS': {},
            'PROTOTYPES': {},
            'LOCALS': {}
        }

        if(main):
            chunk['NAME'] = self.get_string(None)
            if (chunk['NAME']):
                chunk['NAME'] = chunk['NAME'][1:-1]
        else:
            chunk['NAME'] = self.get_size_t()
        print("CHUNK NAME: {}".format(chunk['NAME']))
        chunk['FIRST_LINE'] = self.get_int()
        print("CHUNK FIRST_LINE: {}".format(chunk['FIRST_LINE']))
        chunk['LAST_LINE'] = self.get_int()
        print("CHUNK LAST_LINE: {}".format(chunk['LAST_LINE']))
        chunk['UPVALUES'] = self.get_byte()
        print("CHUNK UPVALUES: {}".format(chunk['UPVALUES']))
        chunk['ARGUMENTS'] = self.get_byte()
        print("CHUNK ARGUMENTS: {}".format(chunk['ARGUMENTS']))
        chunk['VARG'] = self.get_byte()
        print("CHUNK VARG: {}".format(chunk['VARG']))
        print("CHUNK VARARG_HASARG: {}".format(chunk['VARG']&VARARG_HASARG > 0))
        print("CHUNK VARARG_ISVARARG: {}".format(chunk['VARG']&VARARG_ISVARARG > 0))
        print("CHUNK VARARG_NEEDSARG: {}".format(chunk['VARG']&VARARG_NEEDSARG > 0))
        chunk['STACK'] = self.get_byte()
        print("CHUNK STACK: {}".format(chunk['STACK']))

        # parse instructions
        num = self.get_int()
        print("** DECODING INSTRUCTIONS ({})".format(num))
        for i in range(num):
            instruction = {
                # opcode = opcode number;
                # type   = [ABC, ABx, AsBx]
                # A, B, C, Bx, or sBx depending on type
            }

            data   = self.get_int32()
            opcode = get_bits(data, 1, 6)
            if patch:
                org_op_name = lua_opcode_names[opcode]
                op_name = SAMPLE_OPCODE_MAP[org_op_name]
                opcode = OPCODE2INDEX[op_name]
                index = self.index - self.int_size
                self.bytecode_raw[index:self.index] = ((data & 0xFFFFFFC0) ^ opcode).to_bytes(self.int_size, byteorder='big' if self.big_endian else 'little')
            tp   = lua_opcode_types[opcode]

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

            chunk['INSTRUCTIONS'][i] = instruction

            print(format(i,'d').zfill(2), format(data,'b').zfill(32), opcode, lua_opcode_names[opcode], instruction)

        # get constants
        num = self.get_int()
        print("** DECODING CONSTANTS ({})".format(num))
        for i in range(num):
            constant = {
                # type = constant type;
                # data = constant data;
            }
            constant['TYPE'] = self.get_byte()

            if constant['TYPE'] == 1:
                constant['DATA'] = (self.get_byte() != 0)
            elif constant['TYPE'] == 0:
                constant['DATA'] = None
            elif constant['TYPE'] == 3:
                constant['DATA'] = self.get_double()
            elif constant['TYPE'] == 4:
                constant['DATA'] = self.get_string(None)[:-1]
            else:
                constant['DATA'] = self.get_int()

            chunk['CONSTANTS'][i] = constant

            print(format(i,'d').zfill(2), constant)

        # parse protos
        num = self.get_int()
        print("** DECODING PROTOS ({})".format(num))
        for i in range(num):
            print(f"*** PROTO {i:d}:")
            chunk['PROTOTYPES'][i] = self.decode_chunk(main=False, patch=patch)

        # debug stuff
        print("** DECODING DEBUG SYMBOLS")
        # line numbers
        num = self.get_int()
        print("*** LINE NUMBERS ({})".format(num))
        for i in range(num):
            self.get_int32()

        # locals
        num = self.get_int()
        print("*** LOCALS ({})".format(num))
        for i in range(num):
            local_name = self.get_string(None)[:-1]
            local_spc = self.get_int32() # local start PC
            local_epc = self.get_int32() # local end   PC
            chunk['LOCALS'][i] = (local_name, local_spc, local_spc)
            print(local_name, local_spc, local_epc)

        # upvalues
        num = self.get_int()
        print("*** UPVALUES ({})".format(num))
        for i in range(num):
            self.get_string(None) # upvalue name

        self.chunks.append(chunk)

        return chunk

    def decode_bytecode(self, patch=False):
        # alligns index lol
        self.index = 4
        
        self.vm_version = self.get_byte()
        self.bytecode_format = self.get_byte()
        self.big_endian = (self.get_byte() == 0)
        self.int_size   = self.get_byte()
        self.size_t     = self.get_byte()
        self.instr_size = self.get_byte() # gets size of instructions
        self.l_number_size = self.get_byte() # size of lua_Number
        self.integral_flag = self.get_byte()
        

        print("Lua VM version: ", hex(self.vm_version))
        print("big_endian: ", self.big_endian)
        print("int_size: ", self.int_size)
        print("size_t: ", self.size_t)
        print("instr_size size: ", self.instr_size)
        print("l_number_size: ", self.l_number_size)
        print("integral_flag: ", self.integral_flag)

        #print(self.bytecode)
        print(f"HEADER SIZE: {self.index:d}")

        self.chunk = self.decode_chunk(main=True, patch=patch)
        return self.chunk

    def print_dissassembly(self):
        LuaCompiler.dis_chunk(self.chunk)

if __name__ == "__main__":
    with open(sys.argv[1],'rb') as f:
        bytecode = f.read()
        lc = LuaCompiler(bytecode)
        chunk = lc.decode_bytecode(patch=False)
        #lc.dump('old.out')
        #lc.print_dissassembly()
