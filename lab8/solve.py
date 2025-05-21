#!/usr/bin/env python3
import angr
import claripy
import sys

def main():
    proj = angr.Project("./chal")

    key_len = 8
    newline_len = 1
    sym_bytes = [claripy.BVS(f"byte{i}", 8) for i in range(key_len + newline_len)]
    sym_input = claripy.Concat(*sym_bytes)

    state = proj.factory.full_init_state(stdin=sym_input)

    for b in sym_bytes[:key_len]:
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)
    state.solver.add(sym_bytes[-1] == 0x0a)

    sm = proj.factory.simgr(state)
    sm.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))

    if not sm.found:
        print("Can't find Secret key！", file=sys.stderr)
        return

    found = sm.found[0]
    concrete_input = found.solver.eval(sym_input, cast_to=bytes)
    secret_key = concrete_input[:key_len]

    sys.stdout.buffer.write(secret_key)

if __name__ == "__main__":
    main()