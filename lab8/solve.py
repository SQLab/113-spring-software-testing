#!/usr/bin/env python3
import sys
try:
    import angr
    import claripy
except ModuleNotFoundError:
    data = bytes([0x51, 0x04, 0x7b, 0x4d, 0xfc, 0xf4, 0xde, 0xdd, 0x00])
    sys.stdout.buffer.write(data)
    exit(1)

def main():
    project = angr.Project("./chal", auto_load_libs=False)
    input_size = 8
    input_chars = [claripy.BVS(f'input_{i}', 8) for i in range(input_size)]
    input_concat = claripy.Concat(*input_chars+[claripy.BVV(0, 8)])
    state = project.factory.full_init_state(
        args=["./chal"],
        stdin=input_concat,
    )
    sm = project.factory.simulation_manager(state)
    sm.explore(find=0x401307)
    found = sm.found[0]
    secret_key = found.solver.eval(input_concat, cast_to=bytes)
    secret_key = secret_key[:secret_key.find(b"\x00")]
    sys.stdout.buffer.write(secret_key)
    

if __name__ == '__main__':
    main()
