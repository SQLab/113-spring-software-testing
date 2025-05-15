#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # Load the binary
    project = angr.Project("./chal", auto_load_libs=False)

    # Declare 8 symbolic bytes as input
    key_len = 8
    key = [claripy.BVS(f'key{i}', 8) for i in range(key_len)]

    # Concatenate to form a single bitvector
    input_bytes = claripy.Concat(*key)

    # Create symbolic state at program entry
    state = project.factory.full_init_state(
        args=["./chal"],
        stdin=input_bytes
    )

    # Constrain input to be printable (optional but practical)
    for k in key:
        state.solver.add(k >= 0x20)  # space
        state.solver.add(k <= 0x7e)  # ~

    # Set up simulation
    simgr = project.factory.simgr(state)

    # Define success/failure conditions
    def is_successful(state):
        return b"Correct! The flag is:" in state.posix.dumps(1)

    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    # Explore until success
    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(input_bytes, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()