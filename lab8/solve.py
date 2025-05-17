#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    input_chars = [claripy.BVS('', 8) for _ in range(input_len)]
    sym_input = claripy.Concat(*input_chars, claripy.BVV(0, 8))

    # Explicitly use SimFileStream with has_end=False
    stdin_stream = angr.SimFileStream(name='stdin', content=sym_input, has_end=False)

    state = project.factory.entry_state(stdin=stdin_stream)


    for c in input_chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    simgr = project.factory.simgr(state)

    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    simgr.explore(find=is_successful)

    if simgr.found:
        sol = simgr.found[0].solver.eval(claripy.Concat(*input_chars), cast_to=bytes)
        print(sol.decode(), end='')
    else:
        print("[-] No solution found.", end='')


if __name__ == '__main__':
    main()