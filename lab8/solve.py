#!/usr/bin/env python3

import angr
import claripy
import sys


def main():
    # Create the project
    project = angr.Project("./chal")

    # Create a symbolic bitvector for the 8-byte input
    input_size = 8
    sym_input = claripy.BVS("sym_input", input_size * 8)

    # Create an initial state with symbolic stdin
    # The program reads from stdin using fgets
    initial_state = project.factory.entry_state(stdin=sym_input)

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))

    if simgr.found:
        found_state = simgr.found[0]
        # Retrieve the symbolic stdin content
        solution_bytes = found_state.solver.eval(sym_input, cast_to=bytes)
        solution = solution_bytes[:input_size]  # Ensure it's exactly 8 bytes
    else:
        print("No solution found!", file=sys.stderr)
        solution = b""

    sys.stdout.buffer.write(solution)


if __name__ == "__main__":
    main()
