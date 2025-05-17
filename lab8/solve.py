#!/usr/bin/env python3
import angr
import claripy
from angr import options as angr_options
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    # Create symbolic bitvectors: 8 characters, each 8 bits
    input_len = 8
    input_chars = [claripy.BVS(f'char{i}', 8) for i in range(input_len)]
    input_concat = claripy.Concat(*input_chars)

    # Append null terminator to simulate fgets()
    input_with_null = claripy.Concat(input_concat, claripy.BVV(0, 8))

    # Create the initial state and feed symbolic input to stdin
    state = project.factory.full_init_state(
        args=["./chal"],
        stdin=input_with_null
    )
    state.options.add(angr_options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr_options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Constrain input characters to be printable ASCII
    for c in input_chars:
        state.solver.add(c >= 0x20)  # Avoid non-printable characters
        state.solver.add(c <= 0x7e)

    # Explore paths to reach puts("Correct!") and avoid puts("Wrong key!")
    simgr = project.factory.simgr(state)

    def is_successful(s):
        return b"Correct!" in s.posix.dumps(1)

    def is_failed(s):
        return b"Wrong key!" in s.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=is_failed)

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(input_concat, cast_to=bytes)
        print(result.decode())
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
