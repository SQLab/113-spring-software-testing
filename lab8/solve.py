#!/usr/bin/env python3

import angr,sys
import claripy

def main():
    binary = "./chal"
    project = angr.Project(binary, auto_load_libs=False)

    symbolic_input = [claripy.BVS(f'char_{i}', 8) for i in range(8)]
    flag_input = claripy.Concat(*symbolic_input)

    initial_state = project.factory.entry_state(stdin=flag_input)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(
        find=lambda state: b"Correct!" in state.posix.dumps(1),
        avoid=lambda state: b"Wrong key!" in state.posix.dumps(1)
    )

    if simulation.found:
        winning_state = simulation.found[0]
        correct_flag = winning_state.solver.eval(flag_input, cast_to=bytes)
        sys.stdout.buffer.write(correct_flag)
    else:
        print("Unable to find the correct input.", file=sys.stderr)
        sys.exit(1)



if __name__ == '__main__':
    main()
