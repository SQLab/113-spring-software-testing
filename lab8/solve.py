#!/usr/bin/env python3

import sys

try:
    import angr, claripy
except:
    print("fallback", end='')
    sys.exit(0)


def main():
    project = angr.Project('./chal', auto_load_libs=False)

    # Create 8 symbolic bytes
    sym_input = claripy.BVS('sym_input', 8 * 8)
    state = project.factory.full_init_state(stdin=sym_input)

    for b in sym_input.chop(8):
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)

    sm = project.factory.simgr(state)

    #check if the output has a successful msg
    def is_good(state):
        return b"Correct" in state.posix.dumps(1)

    #avoid the wrong output
    def is_bad(state):
        return b"Wrong key" in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        final_state = sm.found[0]
        answer = final_state.solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(answer[:8])  # trim just in case
    else:
        # else fallback if no solution is found
        sys.stdout.buffer.write(b"NO_SOLUTION")


if __name__ == '__main__':
    main()
