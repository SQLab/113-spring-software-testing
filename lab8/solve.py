#!/usr/bin/env python3

import angr,sys
import claripy

def main():
    # secret_key = b""
    # sys.stdout.buffer.write(secret_key)
    proj = angr.Project("./chal", auto_load_libs=False)
    input_size = 8
    sym_input = claripy.BVS("sym_input", 8 * input_size)

    state = proj.factory.full_init_state(
        args=["./chal"],
        stdin=sym_input
    )

    for i in range(input_size):
        byte = sym_input.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)

    simgr = proj.factory.simgr(state)

    def is_successful(s):
        return b"Correct!" in s.posix.dumps(1)

    simgr.explore(find=is_successful)

    if simgr.found:
        found = simgr.found[0]
        secret_key = found.solver.eval(sym_input, cast_to=bytes)
    else:
        secret_key = b""  

    sys.stdout.buffer.write(secret_key)



if __name__ == '__main__':
    main()
