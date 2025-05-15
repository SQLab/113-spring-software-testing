#!/usr/bin/env python3
import angr
import claripy
import sys

def main():
    proj = angr.Project("./chal", auto_load_libs=False)

    chars = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]
    null = claripy.BVV(0, 8)
    input_bytes = claripy.Concat(*chars + [null])

    input_stream = angr.SimFileStream(name='stdin', content=input_bytes, has_end=False)

    state = proj.factory.full_init_state(
        stdin=input_stream,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )

    for c in chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(claripy.Concat(*chars), cast_to=bytes)
        sys.stdout.buffer.write(result)
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
