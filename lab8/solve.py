#!/usr/bin/env python3

import angr
import claripy
import sys

angr.loggers.disable_root_logger()

def is_flag_found(state):
    output = state.posix.dumps(1)
    return b"flag" in output

def main():
    # 載入 binary
    project = angr.Project("./chal", auto_load_libs=False)

    input_len = 100
    input_bits = claripy.BVS("input", input_len * 8)
    symbolic_stdin = angr.SimFile("stdin", content=input_bits, size=input_len)

    initial_state = project.factory.entry_state(stdin=symbolic_stdin)

    simgr = project.factory.simgr(initial_state)

    simgr.explore(find=is_flag_found)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(input_bits, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
