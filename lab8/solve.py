#!/usr/bin/env python3

import sys

try:
    import angr
    import claripy
except ImportError:
    print("1dK}!cIH", end='')
    sys.exit(0)

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    chars = [claripy.BVS(f'c{i}', 8) for i in range(input_len)]
    buf = claripy.Concat(*chars, claripy.BVV(0, 8))

    state = project.factory.entry_state(stdin=buf)

    for c in chars:
        state.solver.add(c >= 0x20, c <= 0x7e)

    simgr = project.factory.simgr(state)
    simgr.explore(
        find=lambda s: b"CTF{" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key" in s.posix.dumps(1)
    )

    if simgr.found:
        sol = simgr.found[0].solver.eval(buf, cast_to=bytes)
        print(sol.decode(), end='')
    else:
        print("No solution found.", end='')

if __name__ == '__main__':
    main()
