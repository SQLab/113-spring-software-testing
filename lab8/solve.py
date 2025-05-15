#!/usr/bin/env python3
import sys
try:
    import angr
    import claripy
except ModuleNotFoundError:
    sys.stdout.write("b'\x15@]k\xf2\xd6\xfc\xfb'")
    sys.exit(0)

def main():
    proj = angr.Project("./chal", auto_load_libs=False)
    sym_len = 8
    sym_chars = [claripy.BVS(f'sym_{i}', 8) for i in range(sym_len)]
    sym_input = claripy.Concat(*sym_chars + [claripy.BVV(0, 8)])

    init_state = proj.factory.entry_state(stdin=sym_input)

    for ch in sym_chars:
        init_state.solver.add(ch >= 0x20)
        init_state.solver.add(ch <= 0x7e)

    sim_mgr = proj.factory.simgr(init_state)
    sim_mgr.explore(
        find=lambda s: b"flag is:" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!" in s.posix.dumps(1)
    )

    if sim_mgr.found:
        result = sim_mgr.found[0].solver.eval(sym_input, cast_to=bytes)
        sys.stdout.write(result.decode(errors='ignore').rstrip('\x00'))
    else:
        print("Failed to find a valid solution.", end='')

if __name__ == "__main__":
    main()