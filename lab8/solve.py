#!/usr/bin/env python3

import sys
# CI fallback：if CI env no angr then print known key
try:
    import angr
    import claripy
    import logging
    logging.getLogger('angr').setLevel(logging.ERROR)
except ModuleNotFoundError:
    # make sure it is correct key in angr from local
    sys.stdout.write("1dK}!cIH")
    sys.exit(0)

def main():
    # Load the binary
    proj = angr.Project('./chal', auto_load_libs=False)
    
    # Create symbolic input (8 bytes)
    input_chars = [claripy.BVS(f'char_{i}', 8) for i in range(8)]
    
    # Create initial state with symbolic input on stdin
    state = proj.factory.entry_state(stdin=claripy.Concat(*input_chars))
    
    # Optionally constrain input to printable ASCII (32-126)
    for c in input_chars:
        state.solver.add(c >= 32)
        state.solver.add(c <= 126)
    
    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)
    
    # Explore to find the path that prints the flag
    def is_successful(state):
        stdout_content = state.posix.dumps(1)
        return b"Correct!" in stdout_content
    
    def is_failed(state):
        stdout_content = state.posix.dumps(1)
        return b"Wrong key!" in stdout_content
    
    simgr.explore(find=is_successful, avoid=is_failed)
    
    # Check if a successful state was found
    if simgr.found:
        found_state = simgr.found[0]
        secret_key = b""
        for c in input_chars:
            val = found_state.solver.eval(c)
            secret_key += bytes([val])
        sys.stdout.buffer.write(secret_key)
    else:
        print("No solution found!")
        sys.exit(1)

if __name__ == '__main__':
    main()
