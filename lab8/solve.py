#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    input_chars = [claripy.BVS(f'c{i}', 8) for i in range(input_len)]
    sym_input = claripy.Concat(*input_chars)
    full_input = claripy.Concat(sym_input, claripy.BVV(0, 8))

    state = project.factory.entry_state(stdin=full_input)

    for c in input_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = project.factory.simgr(state)

    simgr.explore(
        find=lambda s: b"CTF{" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key" in s.posix.dumps(1)
    )

    if simgr.found:
        solution = simgr.found[0].solver.eval(sym_input, cast_to=bytes)
        print(solution.decode(), end='')

if __name__ == '__main__':
    main()
