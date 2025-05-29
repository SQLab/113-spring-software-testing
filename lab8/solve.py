#!/usr/bin/env python3

import angr
import claripy
import sys

def solve_binary(binary_path, input_len=8, success_msg=b"Correct!"):
    proj = angr.Project(binary_path, auto_load_libs=False)

    user_input = claripy.BVS("user_input", input_len * 8)
    state = proj.factory.full_init_state(stdin=user_input)

    simgr = proj.factory.simulation_manager(state)

    def is_successful(s):
        output = s.posix.dumps(sys.stdout.fileno())
        return success_msg in output

    simgr.explore(find=is_successful)

    if simgr.found:
        solution_state = simgr.found[0]
        result = solution_state.solver.eval(user_input, cast_to=bytes)
        return result[:input_len]
    else:
        return b"[!] Not found\n"

def main():
    binary = "./chal"
    flag = solve_binary(binary)
    sys.stdout.buffer.write(flag)

if __name__ == "__main__":
    main()
