#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # Load target file
    proj = angr.Project('./chal', auto_load_libs=False)

    # Create 8 bytes symbolic input
    input_size = 8
    symbolic_input = claripy.BVS('input', input_size * 8)

    # Create initial state, simulate standard input
    state = proj.factory.entry_state(
        stdin=angr.storage.file.SimFileStream(name='stdin', content=symbolic_input, has_end=False),
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )

    # The input is ASCII
    for i in range(input_size):
        byte = symbolic_input.get_byte(i)
        state.solver.add(byte >= 32, byte <= 126)

    simgr = proj.factory.simulation_manager(state)

    # Using objdump to find target addr
    find_addr = 0x401307  # puts("Correct!...") 的地址
    avoid_addr = 0x4013b3  # puts("Wrong key!") 的地址

    simgr.explore(find=find_addr, avoid=avoid_addr)

    # Find correct path
    if simgr.found:
        found_state = simgr.found[0]
        secret_key = found_state.solver.eval(symbolic_input, cast_to=bytes)
        sys.stdout.buffer.write(secret_key)
    else:
        print("No solution found!", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()