#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    buffer_len = 16
    input_len = 8

    chars = [claripy.BVS(f'char{i}', 8) for i in range(input_len)]
    null_term = claripy.BVV(0, 8)
    padding = [claripy.BVV(0, 8) for _ in range(buffer_len - input_len - 1)]
    full_input = claripy.Concat(*chars, null_term, *padding)

    # Create state with symbolic stdin
    state = project.factory.full_init_state(
        args=["./chal"],
        stdin=angr.SimFileStream(name='stdin', content=full_input, has_end=False),
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}  # avoids unknown stack/memory
    )

    for c in chars:
        state.solver.add(c >= 0x20)  # printable ASCII
        state.solver.add(c <= 0x7e)

    simgr = project.factory.simgr(state)

    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(claripy.Concat(*chars), cast_to=bytes)
        sys.stdout.buffer.write(result + b"\n")
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
