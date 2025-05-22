#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # Define the input length and create symbolic variables
    input_len = 8
    chars = [claripy.BVS(f'char_{i}', 8) for i in range(input_len)]
    sym_input = claripy.Concat(*chars)

    # Create initial program state with symbolic stdin
    project = angr.Project("./chal", auto_load_libs=False)
    state = project.factory.full_init_state(
        stdin=angr.SimFileStream(name='stdin', content=sym_input, has_end=True)
    )

    # Constrain characters to be printable ASCII (optional but good practice)
    for c in chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    # Setup simulation manager
    simgr = project.factory.simgr(state)

    # Explore only until we see the success message
    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1),
                  avoid=lambda s: b"Wrong key!" in s.posix.dumps(1))

    # Extract solution
    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(result + b"\n")
    else:
        print("No solution found", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
