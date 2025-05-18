#!/usr/bin/env python3

import angr
import claripy
import sys
import logging

# Suppress Angr warning logs
logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel(logging.ERROR)

# Load the binary without external libraries
global proj
proj = angr.Project('./chal', auto_load_libs=False)

# Create 8 symbolic bytes for the input
sym_bytes = [claripy.BVS(f'c{i}', 8) for i in range(8)]
sym_input = claripy.Concat(*sym_bytes)

# Set up the initial state with our symbolic stdin
state = proj.factory.entry_state(
    stdin=angr.SimFileStream(name='stdin', content=sym_input, has_end=True)
)

# Suppress unconstrained memory/register warnings by zero-filling
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Create a simulation manager
simgr = proj.factory.simgr(state)

# Define success and failure conditions
def is_success(s):
    return b'Correct!' in s.posix.dumps(1)

def is_fail(s):
    return b'Wrong key!' in s.posix.dumps(1)

# Explore to find the successful path
simgr.explore(find=is_success, avoid=is_fail)

if simgr.found:
    found = simgr.found[0]
    solution = found.solver.eval(sym_input, cast_to=bytes)
    sys.stdout.buffer.write(solution)
else:
    print("No solution found!")
