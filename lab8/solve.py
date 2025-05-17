#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    chars = [claripy.BVS('', 8) for _ in range(input_len)]
    buf = claripy.Concat(*chars, claripy.BVV(0, 8))  # Add null terminator!

    state = project.factory.entry_state(stdin=buf)

    for c in chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = project.factory.simgr(state)

    simgr.explore(
        find=lambda s: b"Correct!" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key" in s.posix.dumps(1)
    )

    if simgr.found:
        sol = simgr.found[0].solver.eval(buf, cast_to=bytes)
        print(sol.decode(), end='')  # Print cleanly
    else:
        print("[-] No solution found.", end='')

if __name__ == '__main__':
    main()
