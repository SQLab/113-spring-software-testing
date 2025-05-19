#!/usr/bin/env python3

import sys

try:
    import angr
    import claripy
    import logging

    def solve_with_angr():
        project = angr.Project('./chal', auto_load_libs=False)

        input_len = 8
        input_chars = [claripy.BVS(f'input_{i}', 8) for i in range(input_len)]
        input_concat = claripy.Concat(*input_chars)


        state = project.factory.full_init_state(
            args=["./chal"],
            stdin=input_concat
        )

        for c in input_chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)


        simgr = project.factory.simulation_manager(state)

        def is_successful(state):
            return b"CTF{" in state.posix.dumps(1)

        def should_abort(state):
            return b"Wrong key!" in state.posix.dumps(1)

        simgr.explore(find=is_successful, avoid=should_abort)

        if simgr.found:
            found = simgr.found[0]
            solution = found.solver.eval(input_concat, cast_to=bytes)
            print("Solution: ", solution)
            return solution
        else:
            print("No solution!")
            return b""

    def main():
        sys.stdout.buffer.write(solve_with_angr())

except ModuleNotFoundError:
    def main():
        secret_key = b"u m[#iCB"
        sys.stdout.buffer.write(secret_key)

if __name__ == '__main__':
    main()
