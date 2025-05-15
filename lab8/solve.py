#!/usr/bin/env python3
import angr
import claripy
import sys

def main():
    proj = angr.Project("./chal", auto_load_libs=False)

    # 8 symbolic bytes + null terminator
    chars = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]
    null = claripy.BVV(0, 8)
    input_bytes = claripy.Concat(*chars + [null])

    # Use simpler entry_state() to avoid memory initialization complexity
    state = proj.factory.entry_state(stdin=input_bytes)

    # Constrain input to printable ASCII
    for c in chars:
        state.solver.add(c >= 0x20, c <= 0x7e)

    simgr = proj.factory.simgr(state)

    simgr.explore(
        find=lambda s: b"CTF{" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key" in s.posix.dumps(1)
    )

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(claripy.Concat(*chars), cast_to=bytes)
        print(result.decode(), end='')
    else:
        print("No solution found.", end='')

if __name__ == '__main__':
    main()
