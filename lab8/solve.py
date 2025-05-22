#!/usr/bin/env python3

import angr,sys,claripy

def is_successful(state):
    stdout = state.posix.dumps(sys.stdout.fileno())
    print(stdout)
    if b"CTF" in stdout:
        return True
    return False

def should_abort(state):
    stdout = state.posix.dumps(sys.stdout.fileno())
    if b"Wrong" in stdout:
        return True
    return False


def main():
    proj = angr.Project("chal", auto_load_libs=False)
    
    
    #     add_options = {
    #         angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    #         angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    #     }
    # )
    # inp_ ch = [claripy.BVS('inp_%d', % i, 8) for i in range(9)]
    # inp = claripy.Concat(*inp_ch + [charipy.BVV(b'\n')])
    # for k in inp_ch:
    #     state.solver.add(i >= 32)
    #     state.solver.add(i <= 126)
    
    inp = [claripy.BVS(f'c{i}', 8) for i in range(8)]
    sym_input = claripy.Concat(*inp + [claripy.BVV(b'\n')])
    
    state = proj.factory.entry_state(
        stdin=sym_input,
        add_options = {
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    for i in inp:
        state.solver.add(i >= 32)
        state.solver.add(i <= 126)
    
    
    simgr = proj.factory.simgr()
    simgr.explore(find=is_successful, avoid=should_abort)
    
    secret_key = simgr.found[0].posix.dumps(0)
    
    sys.stdout.buffer.write(secret_key)
    

if __name__ == '__main__':
    main()
