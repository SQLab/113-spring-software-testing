#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    input_chars = [claripy.BVS('', 8) for _ in range(input_len)]
    sym_input = claripy.Concat(*input_chars)

    # Explicitly use SimFileStream with has_end=False
    stdin_stream = angr.SimFileStream(name='stdin', content=sym_input, has_end=False)

    state = project.factory.full_init_state(stdin=stdin_stream)


    for c in input_chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    simgr = project.factory.simgr(state)

    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    simgr.explore(find=is_successful)

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(result)


if __name__ == '__main__':
    main()