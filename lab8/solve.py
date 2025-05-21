#!/usr/bin/env python3

import angr, sys
import claripy

def main():
    secret_key = b""

    proj = angr.Project('./chal', auto_load_libs=False)
    input_key = [claripy.BVS(f'input_{i}', 8) for i in range(8)]
    inputs = claripy.Concat(*input_key)
    stdin = angr.SimFileStream(name='stdin', content=inputs, has_end=False) # avoid error 1
    # state = proj.factory.full_init_state(stdin=inputs)
    state = proj.factory.full_init_state(stdin=stdin)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)  # avoid error 2
    for i in input_key:
        state.solver.add(i >= 0x20)
        state.solver.add(i <= 0x7e)
    
    simgr = proj.factory.simgr(state)
    
    def find_function(state):
        return b'Correct! The flag is: CTF{symbolic_execution_for_the_win}' in state.posix.dumps(1)
    def avoid_function(state):
        return b'Wrong key!' in state.posix.dumps(1)
    
    simgr.explore(find=find_function, avoid=avoid_function)
    
    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(inputs, cast_to=bytes)    

        sys.stdout.buffer.write(result)


if __name__ == '__main__':
    main()
