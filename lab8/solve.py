#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # 創建 angr 專案
    proj = angr.Project('./chal', auto_load_libs=False)
    
    # 創建符號輸入
    input_size = 8
    # 創建 8 個符號字元
    sym_chars = [claripy.BVS(f'char_{i}', 8) for i in range(input_size)]
    # 將字元連接成一個字串
    sym_input = claripy.Concat(*sym_chars)
    
    # 創建初始狀態
    state = proj.factory.entry_state(stdin=sym_input)
    
    # 添加約束條件
    for char in sym_chars:
        state.solver.add(char >= 0x20)  # 可列印字元
        state.solver.add(char <= 0x7e)
    
    # 創建模擬管理器
    simgr = proj.factory.simulation_manager(state)
    
    # 探索直到找到目標
    simgr.explore(
        find=lambda s: b"Correct!" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!" in s.posix.dumps(1)
    )
    
    if len(simgr.found) > 0:
        # 獲取找到的解決方案
        solution = simgr.found[0].solver.eval(sym_input, cast_to=bytes)
        # 輸出密鑰
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()