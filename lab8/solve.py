#!/usr/bin/env python3

import sys
import angr
import claripy

def main():
    proj = angr.Project("./chal", auto_load_libs=False)
    flag_bytes = [claripy.BVS(f'flag_{i}', 8) for i in range(8)]
    flag = claripy.Concat(*flag_bytes)

    state = proj.factory.entry_state(stdin=flag)

    simgr = proj.factory.simgr(state)
    simgr.explore(
        find=lambda s: b"Correct!" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!" in s.posix.dumps(1)
    )

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found!", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
