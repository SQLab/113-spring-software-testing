#!/usr/bin/env python3
import angr
import claripy
import sys

def main():
    # 載入二進位，不載入動態函式庫加快速度
    proj = angr.Project('./chal', auto_load_libs=False)

    # 建立 8 個符號字元
    flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(8)]
    flag = claripy.Concat(*flag_chars)

    # 製作帶有符號輸入的初始狀態
    # has_end=True 表示讀到 flag 後即結束輸入
    stdin = angr.SimFileStream(name='stdin', content=flag, has_end=True)
    state = proj.factory.full_init_state(stdin=stdin)

    # 限制每個字元為可列印 ASCII（32~126）
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = proj.factory.simulation_manager(state)

    # 尋找印出「Correct! The flag is」的路徑
    target = b"Correct! The flag is"
    simgr.explore(find=lambda s: target in s.posix.dumps(1))

    if simgr.found:
        found = simgr.found[0]
        # 求解出具體 key
        solution = found.solver.eval(flag, cast_to=bytes)
        # 輸出到 stdout，供 validate.sh 傳給 chal
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found.", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
