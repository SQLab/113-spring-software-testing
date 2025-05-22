#!/usr/bin/env python3
import sys
import angr
import claripy

def main():
    proj = angr.Project('./chal', auto_load_libs=False)
    
    input_size = 8
    sym_chars = [claripy.BVS(f'char_{i}', 8) for i in range(input_size)]
    sym_input = claripy.Concat(*sym_chars)
    
    state = proj.factory.entry_state(stdin=sym_input)
    
    for char in sym_chars:
        state.solver.add(char >= 0x20)  # 可列印字元
        state.solver.add(char <= 0x7e)
    
    simgr = proj.factory.simulation_manager(state)
    
    simgr.explore(
        find=lambda s: b"Correct!" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!" in s.posix.dumps(1)
    )
    
    if len(simgr.found) > 0:
        solution = simgr.found[0].solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()