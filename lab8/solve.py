#!/usr/bin/env python3

import angr,sys
import claripy

def main():

    #新建專案且不自動載入函式庫
    proj = angr.Project('./chal', auto_load_libs=False)

    #建立8-bit輸入
    sym_chars = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]
    sym_input = claripy.Concat(*sym_chars)

    #初始化執行狀態並模擬stdin輸入
    state = proj.factory.full_init_state(
        stdin = angr.SimFileStream(name='stdin', content=sym_input, has_end=True)
    )

    #建立模擬器並開始搜尋個別狀態
    simgr = proj.factory.simgr(state)
    simgr.explore(
        find = lambda s:b"Correct!" in s.posix.dumps(1)
    )

    #找到則輸出結果，否則輸出 "No solution found!"
    if simgr.found:
        found = simgr.found[0]
        secret_key = found.solver.eval(sym_input, cast_to=bytes)
        sys.stdout.buffer.write(secret_key)
    else:
        print("No solution found!")
        sys.exit(1)


if __name__ == '__main__':
    main()
