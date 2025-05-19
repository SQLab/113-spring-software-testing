#!/usr/bin/env python3

import angr, sys

def main():
    proj = angr.Project("./chal")
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    def is_successful(state):
        return b"Correct!" in state.stdout.contents

    def should_abort(state):
        return b"Wrong key!" in state.stdout.contents

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found_state = simgr.found[0]
        input_arg = found_state.posix.stdin.load(0, 8)
        solution = found_state.solver.eval(input_arg, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("Could not find the secret key.")

if __name__ == '__main__':
    main()