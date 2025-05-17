#!/usr/bin/env python3
import sys
import claripy

def main():
    bvs = [claripy.BVS(f'k{i}', 32) for i in range(8)]
    solver = claripy.Solver()

    for x in bvs:
        solver.add(x >= 0)
        solver.add(x <= 255)

    solver.add(bvs[0] ^ bvs[1] == 0x55)
    solver.add(bvs[2] + bvs[3] == 200)
    solver.add(bvs[4] * 3 == bvs[5])
    solver.add(bvs[6] - bvs[7] == 1)
    solver.add(bvs[1] + bvs[2] - bvs[3] == 50)
    solver.add(bvs[5] ^ bvs[6] == 0x2A)

    for x in bvs:
        solver.add(x >= 0x20)
        solver.add(x <= 0x7e)
        solver.add(x != 0x0a)

    if solver.satisfiable():
        vals = [solver.eval(x, 1)[0] for x in bvs]
        solution = bytes(vals)
        hex_str = " ".join(f"{v:02x}" for v in vals)
        ascii_str = solution.decode('ascii', errors='replace')
        sys.stdout.buffer.write(solution)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
