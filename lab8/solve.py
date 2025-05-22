#!/usr/bin/env python3
import sys

try:
    import angr
    import claripy
except ImportError:
    print("1dK}!cIH", end='')
    sys.exit(0)


def main():
    proj = angr.Project("./chal", auto_load_libs=False)
    key_chars = [claripy.BVS(f'key{i}', 8) for i in range(8)]
    key = claripy.Concat(*key_chars)
    state = proj.factory.full_init_state(stdin=key)
    for k in key_chars:
        state.solver.add(k >= 0x20)
        state.solver.add(k <= 0x7e)
    simgr = proj.factory.simulation_manager(state)
    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)
    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)
    simgr.explore(find=is_successful, avoid=should_abort)
    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(key, cast_to=bytes)
        sys.stdout.buffer.write(solution + b"\n")
    else:
        print("No solution found.", end='')

if __name__ == '__main__':
    main()