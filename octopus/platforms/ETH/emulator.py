from octopus.engine.emulator import EmulatorEngine
from octopus.core.ssa import SSA, SSA_TYPE_FUNCTION, SSA_TYPE_CONSTANT

from octopus.platforms.ETH.vmstate import EthereumVMstate

from octopus.platforms.ETH.disassembler import EthereumDisassembler
from octopus.platforms.ETH.ssa import EthereumSSASimplifier

from octopus.engine.helper import helper as hlp

import copy

from eth_hash.auto import keccak

from logging import getLogger
logging = getLogger(__name__)


class EthereumEmulatorEngine(EmulatorEngine):

    def __init__(self, bytecode, ssa=True, symbolic_exec=False, max_depth=20):

        self.ssa = ssa
        self.symbolic_exec = symbolic_exec

        # retrive instructions, basicblocks & functions statically
        disasm = EthereumDisassembler(bytecode)
        self.instructions = disasm.disassemble()
        self.reverse_instructions = {k: v for k, v in enumerate(self.instructions)}

        self.simplify_ssa = EthereumSSASimplifier()

        self.states = dict()
        self.states_total = 0
        self.max_depth = max_depth
        self.ssa_counter = 0

    def emulate(self, callinfo, state=EthereumVMstate(), depth=0):

        # custom code block
        new_state = EthereumVMstate()
        new_state.storage = state.storage
        state = new_state
        # custom code block end

        #  create fake stack for tests
        state.symbolic_stack = list(range(1000))

        # get current instruction
        instr = self.reverse_instructions[state.pc]

        # halt variable use to catch ending branch
        halt = False
        while not halt:

            # get current instruction
            instr = self.reverse_instructions[state.pc]

            # Save instruction and state
            state.instr = instr
            self.states[self.states_total] = state
            #state = copy.deepcopy(state)
            self.states_total += 1
            state.pc += 1

            # execute single instruction
            halt = self.emulate_one_instruction(callinfo, instr, state, depth)


    def emulate_one_instruction(self, callinfo, instr, state, depth):
        if instr.operand_interpretation:
            print ('\033[1;32m Instr \033[0m',hex(state.pc-1), instr.name, hex(instr.operand_interpretation))
        else:
            print ('\033[1;32m Instr \033[0m', hex(state.pc-1), instr.name)

        halt = False

        #
        #  0s: Stop and Arithmetic Operations
        #
        if instr.name == 'STOP':
            if self.ssa:
                instr.ssa = SSA(method_name=instr.name)
            halt = True
        elif instr.is_arithmetic:
            self.emul_arithmetic_instruction(instr, state)
        #
        #  10s: Comparison & Bitwise Logic Operations
        #
        elif instr.is_comparaison_logic:
            self.emul_comparaison_logic_instruction(instr, state)
        #
        #  20s: SHA3
        #
        elif instr.is_sha3:
            self.emul_sha3_instruction(instr, state)
        #
        #  30s: Environment Information
        #
        elif instr.is_environmental:
            self.ssa_environmental_instruction(callinfo, instr, state)
        #
        #  40s: Block Information
        #
        elif instr.uses_block_info:
            self.ssa_block_instruction(instr, state)
        #
        #  50s: Stack, Memory, Storage, and Flow Information
        #
        elif instr.uses_stack_block_storage_info:
            halt = self.ssa_stack_memory_storage_flow_instruction(callinfo, instr, state, depth)
        #
        #  60s & 70s: Push Operations
        #
        elif instr.name.startswith("PUSH"):
            #value = int.from_bytes(instr.operand, byteorder='big')
            instr.ssa = SSA(self.ssa_counter, instr.name,
                            instr.operand_interpretation,
                            instr_type=SSA_TYPE_CONSTANT)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

            # custome new code block
            state._stack.append(instr.operand_interpretation)
            # custome new code block end

        #
        #  80s: Duplication Operations
        #
        elif instr.name.startswith('DUP'):
            # DUPn (eg. DUP1: a b c -> a b c c, DUP3: a b c -> a b c a)
            position = instr.pops  # == XX from DUPXX
            try:
                # SSA STACK
                instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=[state.ssa_stack[- position]])
                state.ssa_stack.append(state.ssa_stack[- position])
                self.ssa_counter += 1
                halt = False
            except:
                logging.info('[-] STACK underflow')
                halt = True

            # custome new code block
            state._stack.append(state._stack[- position])
            # custome new code block end
        #
        #  90s: Swap Operations
        #
        elif instr.name.startswith('SWAP'):
            # SWAPn (eg. SWAP1: a b c d -> a b d c, SWAP3: a b c d -> d b c a)
            position = instr.pops - 1  # == XX from SWAPXX
            try:
                temp = state.ssa_stack[-position - 1]
                state.ssa_stack[-position - 1] = state.ssa_stack[-1]
                state.ssa_stack[-1] = temp

                instr.ssa = SSA(method_name=instr.name, args=[temp])

                halt = False
            except:
                logging.warning('[-] STACK underflow')
                halt = True
                #raise ValueError('STACK underflow')

            # custome new code block

            temp = state._stack[-position - 1]
            state._stack[-position - 1] = state._stack[-1]
            state._stack[-1] = temp
            # custome new code block end

        #
        #  a0s: Logging Operations
        #
        elif instr.name.startswith('LOG'):
            # only stack operations emulated
            arg = [state.ssa_stack.pop() for x in range(instr.pops)]
            instr.ssa = SSA(method_name=instr.name, args=arg)
            #state.ssa_stack.append(instr)
        #
        #  f0s: System Operations
        #
        elif instr.is_system:
            halt = self.ssa_system_instruction(instr, state)
            #ssa.append(instr.name)

        # UNKNOWN INSTRUCTION
        else:
            logging.warning('UNKNOWN = ' + instr.name)

        print ('stack: ',list(map(lambda x: hex(x),state._stack)))
        print ('storage: ', state.storage)
        #print ('memory: ', state.memory)
        return halt

    def emul_arithmetic_instruction(self, instr, state):

        if instr.name in ['ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'SDIV', 'SMOD', 'EXP', 'SIGNEXTEND']:
            args = [state.ssa_stack.pop(), state.ssa_stack.pop()]
        elif instr.name in ['ADDMOD', 'MULMOD']:
            args = [state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()]

        # SSA emulation
        if self.ssa:
            instr.ssa = SSA(self.ssa_counter,
                            instr.name, args=args)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

        # Symbolic Execution emulation
        if self.symbolic_exec:
            result = self.simplify_ssa.symbolic_dispatcher(instr.name, args)
            state.stack.append(result)

        # custome new code block
        op = instr.name

        if op == 'ADD':
            s0 = hlp.convert_to_bitvec(state._stack.pop())
            s1 = hlp.convert_to_bitvec(state._stack.pop())
            state._stack.append(hlp.get_concrete_int(s0 + s1))
        elif op == 'SUB':
            s0 = hlp.convert_to_bitvec(state._stack.pop())
            s1 = hlp.convert_to_bitvec(state._stack.pop())
            state._stack.append(hlp.get_concrete_int(s0 - s1))
        elif op == 'MUL':
            s0 = hlp.convert_to_bitvec(state._stack.pop())
            s1 = hlp.convert_to_bitvec(state._stack.pop())
            state._stack.append(hlp.get_concrete_int(s0 * s1))
        elif op == 'DIV':
            x = state._stack.pop()
            y = state._stack.pop()
            if y == 0:
                state._stack.append(0)
            else:
                state._stack.append(hlp.get_concrete_int(x//y))
        elif op == 'MOD':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(0 if y == 0 else x % y))
        # TODO: signed int
        elif op == 'SDIV':
            x = state._stack.pop()
            y = state._stack.pop()
            sign = -1 if (x // y) < 0 else 1
            computed = sign * (abs(x) // abs(y))
            state._stack.append(hlp.get_concrete_int(computed))
        elif op == 'SMOD':
            x = state._stack.pop()
            y = state._stack.pop()
            sign = -1 if x < 0 else 1
            computed = sign * (abs(x) % abs(y))
            state._stack.append(hlp.get_concrete_int(computed))
        elif op == 'EXP':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(pow(x, y)))
        elif op == 'SIGNEXTEND':
            i = state._stack.pop()
            x = state._stack.pop()
            sign = (x).to_bytes(32, byteorder="big")[(pow(i, 8)+7)]
            val = bytearray(32)
            val[0] = sign
            val[(pow(i, 8)+7):] = (x).to_bytes(32, byteorder="big")[(pow(i, 8)+7):]

            state._stack.append(hlp.get_concrete_int(val))
        elif op == 'ADDMOD':
            x = state._stack.pop()
            y = state._stack.pop()
            m = state._stack.pop()
            state._stack.append(hlp.get_concrete_int((x+y)%m))
        elif op == 'MULMOD':
            x = state._stack.pop()
            y = state._stack.pop()
            m = state._stack.pop()
            state._stack.append(hlp.get_concrete_int((x*y)%m))
        # custome new code block end

    def emul_comparaison_logic_instruction(self, instr, state):

        if instr.name in ['LT', 'GT', 'SLT', 'SGT',
                          'EQ', 'AND', 'OR', 'XOR', 'BYTE']:
            args = [state.ssa_stack.pop(), state.ssa_stack.pop()]

        elif instr.name in ['ISZERO', 'NOT']:
            args = [state.ssa_stack.pop()]

        # SSA emulation
        if self.ssa:
            instr.ssa = SSA(self.ssa_counter,
                            instr.name, args=args)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

        # Symbolic Execution emulation
        if self.symbolic_exec:
            result = self.simplify_ssa.symbolic_dispatcher(instr.name, args)
            state.stack.append(result)

        # custome new code block
        op = instr.name

        if op == 'LT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x < y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'GT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x > y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        # TODO: signed compare
        elif op == 'SLT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x < y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'SGT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x > y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'EQ':
            x = state._stack.pop()
            y = state._stack.pop()
            if x == y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'AND':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x&y)
        elif op == 'OR':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x|y)
        elif op == 'XOR':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x^y)
        elif op == 'BYTE':
            n = state._stack.pop()
            x = state._stack.pop()
            state._stack.append(int((x).to_bytes(32, byteorder="big")[n]))
        elif op == 'ISZERO':
            x = state._stack.pop()
            if x == 0:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'NOT':
            x = state._stack.pop()
            state._stack.append(~x)
        # custome new code block end


    def emul_sha3_instruction(self, instr, state):
        '''Symbolic execution of SHA3 group of opcode'''

        # SSA STACK
        s0, s1 = state.ssa_stack.pop(), state.ssa_stack.pop()
        instr.ssa = SSA(self.ssa_counter, instr.name, args=[s0, s1])
        state.ssa_stack.append(instr)
        self.ssa_counter += 1
        # custome new code block
        pos = state._stack.pop()
        n = state._stack.pop()
        sha3 = int(keccak(state.memory[pos:pos+n]).hex(),16)
        # TODO
        state._stack.append(sha3)
        # custome new code block end

    def ssa_environmental_instruction(self, callinfo, instr, state):

        if instr.name in ['ADDRESS', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATASIZE', 'CODESIZE', 'RETURNDATASIZE', 'GASPRICE']:
            # SSA STACK
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1
            # custome new code block
            op = instr.name
            if op == 'CALLDATASIZE':
                v = len(callinfo["calldata"])
                state._stack.append(v)
            elif op == 'CALLVALUE':
                v = callinfo['callvalue']
                state._stack.append(v)
            else:
                state._stack.append(0xbadbeef)
            # custome new code block end

        elif instr.name in ['BALANCE', 'CALLDATALOAD', 'EXTCODESIZE']:
            # SSA STACK
            s0 = state.ssa_stack.pop()
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=[s0])
            state.ssa_stack.append(instr)
            self.ssa_counter += 1
            # custome new code block
            if instr.name == 'CALLDATALOAD':
                pos = state._stack.pop()
                pos_end = pos + 0x20

                v = int(callinfo["calldata"][pos:pos_end].hex(),16)
                #print('calldata metadata: ', hex(v))
                state._stack.append(v)
            else:
                state._stack.append(0xbadbeef)
            # custome new code block end

        elif instr.name in ['CALLDATACOPY', 'CODECOPY', 'RETURNDATACOPY']:
            op0, op1, op2 = state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()
            # SSA STACK
            instr.ssa = SSA(method_name=instr.name, args=[op0, op1, op2])
            # custome new code block
            op0 = state._stack.pop()
            op1 = state._stack.pop()
            op2 = state._stack.pop()
            # custome new code block end


        elif instr.name == 'EXTCODECOPY':
            addr = state.ssa_stack.pop()
            start, s2, size = state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()
            # SSA STACK
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=[addr, start, s2, size])
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

            # custome new code block
            addr = state._stack.pop()
            start = state._stack.pop()
            s2 = state._stack.pop()
            size = state._stack.pop()
            state._stack.append(0xbadbeef)
            # custome new code block end

    def ssa_block_instruction(self, instr, state):

        if instr.name == 'BLOCKHASH':
            # SSA STACK
            blocknumber = state.ssa_stack.pop()
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=[blocknumber])
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

            # custome new code block
            blocknumber = state._stack.pop()
            state._stack.append(0xbadbeef)
            # custome new code block end

        elif instr.name in ['COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT']:
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name)
            state.ssa_stack.append(instr)
            # custome new code block
            state._stack.append(0xbadbeef)
            # custome new code block end
            self.ssa_counter += 1

    def ssa_stack_memory_storage_flow_instruction(self, callinfo, instr, state, depth):

        halt = False
        op = instr.name

        if op == 'POP':
            # SSA STACK
            s0 = state.ssa_stack.pop()
            instr.ssa = SSA(method_name=instr.name)

            # custome new code block
            state._stack.pop()
            # custome new code block end


        elif op in ['MLOAD', 'SLOAD']:
            # SSA STACK
            s0 = state.ssa_stack.pop()
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=[s0])
            state.ssa_stack.append(instr)

            # custome new code block
            
            if op == 'MLOAD':
                mem_pos = state._stack.pop()
                #mem_end = mem_pos + 0x20
                #mem_val = int(state.memory[mem_pos:mem_end].hex(),16)
                mem_val = state.memory.mload(mem_pos)
                state._stack.append(mem_val)

            if op == 'SLOAD':
                storage_pos = state._stack.pop()
                #storage_val = state.storage[storage_pos]
                storage_val = state.storage.sload(storage_pos)
                state._stack.append(storage_val)

            # custome new code block end

            self.ssa_counter += 1

        elif op in ['MSTORE', 'MSTORE8', 'SSTORE']:
            # SSA STACK
            s0, s1 = state.ssa_stack.pop(), state.ssa_stack.pop()
            instr.ssa = SSA(method_name=instr.name, args=[s0, s1])

            # custome new code block
            if op == 'MSTORE':
                pos = state._stack.pop()
                #pos_end = pos + 0x20
                val = state._stack.pop()
                #if len(state.memory) < pos_end:
                #    state.memory.extend(bytearray(pos_end))
                #state.memory[pos:pos_end] = (val).to_bytes(32, byteorder="big")
                state.memory.mstore(pos,val)
            elif op == 'MSTORE8':
                pos = state._stack.pop()
                val = state._stack.pop()
                #if len(state.memory) < pos_end:
                #    state.memory.extend(bytearray(pos_end))
                #state.memory[pos:pos] = (val).to_bytes(1, byteorder="big")
                state.memory.mstore8(pos,val)

            elif op == 'SSTORE':
                pos = state._stack.pop()
                val = state._stack.pop()
                #state.storage[pos] = val
                state.storage.sstore(pos,val)
            # custome new code block end

        elif op == 'JUMP':
            # SSA STACK
            push_instr = state.ssa_stack.pop()
            instr.ssa = SSA(method_name=instr.name, args=[push_instr])

            # custome new code block
            state._stack.pop()
            # custome new code block end

            # get instruction with this value as offset
            if push_instr.ssa.is_constant:
                #jump_addr = int.from_bytes(push_instr.operand, byteorder='big')
                jump_addr = push_instr.operand_interpretation
                # get instruction with this value as offset
                target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
            else:
                # try to resolve the SSA repr
                jump_addr = self.simplify_ssa.resolve_instr_ssa(push_instr)
                target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
                if not jump_addr:
                    logging.warning('JUMP DYNAMIC')
                    logging.warning('[X] push_instr %x: %s ' % (push_instr.offset, push_instr.name))
                    logging.warning('[X] push_instr.ssa %s' % push_instr.ssa.format())
                    list_args = [arg.ssa.format() for arg in push_instr.ssa.args]
                    logging.warning('[X] push_instr.ssa %s' % list_args)
                    return True

            # depth of 1 - prevent looping
            #if (depth < self.max_depth):
            if target.name != "JUMPDEST":
                logging.info('[X] Bad JUMP to 0x%x' % jump_addr)
                return True

            new_state = state
            new_state.pc = self.instructions.index(target)
            #self.emulate(callinfo, new_state, depth=depth + 1)

            #return True

            # custom new code block end

        elif op == 'JUMPI':
            # SSA STACK
            push_instr, condition = state.ssa_stack.pop(), state.ssa_stack.pop()
            # custome new code block
            label = state._stack.pop()
            con = state._stack.pop()
            # custome new code block end
            instr.ssa = SSA(method_name=instr.name, args=[push_instr, condition])

            logging.info('[X] follow JUMPI default branch offset 0x%x' % (instr.offset_end + 1))
            #new_state = copy.deepcopy(state)
            #self.edges.append(Edge(self.current_basicblock.name, 'block_%x'%(instr.offset_end + 1), EDGE_CONDITIONAL_FALSE))
            #self.emulate(callinfo, new_state, depth=depth + 1)
            #self.current_basicblock = self.basicblock_per_instr[instr.offset]

            # get instruction with this value as offset
            if push_instr.ssa.is_constant:
                #jump_addr = int.from_bytes(push_instr.operand, byteorder='big')
                jump_addr = push_instr.operand_interpretation
                # get instruction with this value as offset
                target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
            else:
                # try to resolve the SSA repr
                jump_addr = self.simplify_ssa.resolve_instr_ssa(push_instr)
                target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
                if not jump_addr:
                    logging.warning('JUMP DYNAMIC')
                    logging.warning('[X] push_instr %x: %s ' % (push_instr.offset, push_instr.name))
                    logging.warning('[X] push_instr.ssa %s' % push_instr.ssa.format())
                    list_args = [arg.ssa.format() for arg in push_instr.ssa.args]
                    logging.warning('[X] push_instr.ssa %s' % list_args)
                    return True

            if target.name != "JUMPDEST":
                logging.info('[X] Bad JUMP to 0x%x' % jump_addr)
                return True

            #if target.offset not in state.instructions_visited:
            if con:
                # condition are True
                new_state = state
                new_state.pc = self.instructions.index(target)

            else:
                new_state = state
                #halt = True
            #halt = True

        elif op in ['PC', 'MSIZE', 'GAS']:
            # SSA STACK
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name)
            state.ssa_stack.append(instr)

            # custome new code block
            state._stack.append(0xbadbeef)
            # custome new code block end

            self.ssa_counter += 1

        elif op == 'JUMPDEST':
            # SSA STACK
            instr.ssa = SSA(method_name=instr.name)

        return halt

    def ssa_system_instruction(self, instr, state):

        halt = False

        if instr.name == 'CREATE':
            args = [state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()]
            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=args)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

        elif instr.name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):

            if instr.name in ('CALL', 'CALLCODE'):
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                    state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()
                args = [gas, to, value, meminstart, meminsz, memoutstart, memoutsz]

            else:
                gas, to, meminstart, meminsz, memoutstart, memoutsz = \
                    state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop(), state.ssa_stack.pop()
                args = [gas, to, meminstart, meminsz, memoutstart, memoutsz]

            instr.ssa = SSA(new_assignement=self.ssa_counter, method_name=instr.name, args=args)
            state.ssa_stack.append(instr)
            self.ssa_counter += 1

        elif instr.name in ['RETURN', 'REVERT']:
            offset, length = state.ssa_stack.pop(), state.ssa_stack.pop()
            instr.ssa = SSA(method_name=instr.name, args=[offset, length])
            halt = True

        elif instr.name in ['INVALID', 'SELFDESTRUCT']:
            # SSA STACK
            instr.ssa = SSA(method_name=instr.name)
            halt = True

        return halt


class EthereumSSAEngine(EthereumEmulatorEngine):

    def __init__(self, bytecode=None, max_depth=20):
        EthereumEmulatorEngine.__init__(self, bytecode=bytecode,
                                        ssa=True,
                                        symbolic_exec=False,
                                        max_depth=max_depth)
