#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # 載入二進位，不要自動載入系統函式庫
    proj = angr.Project('./chal', auto_load_libs=False)

    # 創建 8 個符號變數，每個 8 bits
    sym_bytes = [claripy.BVS(f'c{i}', 8) for i in range(8)]
    sym_input = claripy.Concat(*sym_bytes)

    # 建立 entry state，stdin 就是我們的 8 字元符號串
    state = proj.factory.entry_state(
        stdin=angr.SimFileStream(name='stdin', content=sym_input, has_end=True)
    )

    simgr = proj.factory.simgr(state)

    # 找到印出 "Correct!" 的狀態，並避開印出 "Wrong key!" 的分支
    def is_success(s):
        return b'Correct!' in s.posix.dumps(1)

    def is_fail(s):
        return b'Wrong key!' in s.posix.dumps(1)

    simgr.explore(find=is_success, avoid=is_fail)

    if simgr.found:
        found = simgr.found[0]
        # 解出具體的 byte sequence
        solution = found.solver.eval(sym_input, cast_to=bytes)
        # 輸出到 stdout，讓 Makefile 的管道能接到
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found!")

if __name__ == '__main__':
    main()
