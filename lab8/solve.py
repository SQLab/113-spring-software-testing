#!/usr/bin/env python3
import sys
import angr
import claripy

def solve_with_angr():
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 9
    input_chars = [claripy.BVS(f'input_{i}', 8) for i in range(input_len)]
    input_concat = claripy.Concat(*input_chars)

    state = project.factory.full_init_state(
        args=["./chal"],
        stdin=input_concat
    )

    for c in input_chars[:-1]:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)
    state.solver.add(input_chars[-1] == 0x0a)

    simgr = project.factory.simulation_manager(state)

    def is_successful(state):
        return b"CTF{" in state.posix.dumps(1)

    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(claripy.Concat(*input_chars[:-1]), cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        sys.stdout.buffer.write(b"")  # fallback or nothing

if __name__ == '__main__':
    solve_with_angr()