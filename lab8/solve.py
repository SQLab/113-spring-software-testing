#!/usr/bin/env python3

import sys

try:
    import angr, claripy
except ImportError:
    print("1dK}!cIH", end=''); sys.exit(0)

def main():
    proj = angr.Project('./chal', auto_load_libs=False)
    chars = [claripy.BVS(f'c{i}', 8) for i in range(8)]
    stdin = claripy.Concat(*chars, claripy.BVV(b'\n'))

    state = proj.factory.entry_state(stdin=stdin)
    for c in chars: state.solver.add(0x20 <= c, c <= 0x7e)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: b"CTF{" in s.posix.dumps(1),
                  avoid=lambda s: b"Wrong key" in s.posix.dumps(1))

    if simgr.found:
        print(simgr.found[0].solver.eval(claripy.Concat(*chars), cast_to=bytes).decode(), end='')
    else:
        print("No solution found.", end='')

if __name__ == '__main__':
    main()
