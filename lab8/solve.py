#!/usr/bin/env python3
import sys
from z3 import BitVec, Solver, And, sat

def main():
    # 建立 8 個 32-bit BitVec 變數
    bvs = [BitVec(f'k{i}', 32) for i in range(8)]
    solver = Solver()

    # 0 <= xi <= 255
    for x in bvs:
        solver.add(And(x >= 0, x <= 255))

    # 約束條件
    solver.add(bvs[0] ^ bvs[1] == 0x55)
    solver.add(bvs[2] + bvs[3] == 200)
    solver.add(bvs[4] * 3 == bvs[5])
    solver.add(bvs[6] - bvs[7] == 1)
    solver.add(bvs[1] + bvs[2] - bvs[3] == 50)
    solver.add(bvs[5] ^ bvs[6] == 0x2A)

    # 限制為可列印 ASCII 字元 (0x20–0x7e)，且不等於換行符
    for x in bvs:
        solver.add(And(x >= 0x20, x <= 0x7e, x != 0x0A))

    # 求解並輸出
    if solver.check() == sat:
        model = solver.model()
        vals = [model[x].as_long() for x in bvs]
        solution = bytes(vals)
        # 如果需要十六進制或 ASCII 字串可以這樣：
        hex_str = " ".join(f"{v:02x}" for v in vals)
        ascii_str = solution.decode('ascii', errors='replace')
        # 直接把原始 bytes 寫到 stdout
        sys.stdout.buffer.write(solution)
        # 以下兩行可選：印出 hex / ASCII 方便檢查
        # print("\nhex:", hex_str)
        # print("ascii:", ascii_str)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
