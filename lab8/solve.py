#!/usr/bin/env python3

import angr
import claripy
import sys

angr.loggers.disable_root_logger()

def is_flag_found(state):
    output = state.posix.dumps(1)
    return b"flag" in output

def main():
    project = angr.Project("./chal", auto_load_libs=False)

    sym_chars = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]
    sym_input = claripy.Concat(*sym_chars)

    state = project.factory.full_init_state(
        stdin = angr.SimFileStream(name='stdin', content=sym_input, has_end=True)
    )


    simgr = project.factory.simgr(state)

    simgr.explore(
        find = lambda s:b"Correct!" in s.posix.dumps(1)
    )

    if simgr.found:
        found = simgr.found[0]
        secret_key = found.solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(secret_key)
    else:
        print("No solution found!")
        sys.exit(1)


if __name__ == '__main__':
    main()
