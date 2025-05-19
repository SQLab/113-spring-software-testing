#!/usr/bin/env python3

import sys 
try:
    import angr
    import claripy
except ModuleNotFoundError:
    sys.stdout.write("m8ag#iCB")
    sys.exit(0)

def main():
    # 定義 symbolic input：8 個位元組（每個 8-bit）
    input_len = 8
    input_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(input_len)]
    secret_key = claripy.Concat(*input_bytes)

    # 建立 angr 專案
    proj = angr.Project('./chal', auto_load_libs=False)

    # 使用 SimFileStream 包裝 symbolic stdin，避免 has_end=True 的警告
    stdin = angr.SimFileStream(name='stdin', content=secret_key, has_end=False)
    state = proj.factory.full_init_state(args=["./chal"], stdin=stdin)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # 限制輸入為可列印 ASCII
    for byte in input_bytes:
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)

    # 建立模擬管理器
    simgr = proj.factory.simgr(state)

    # 成功與失敗的判斷依據
    def is_successful(state):
        return b"Correct! The flag is:" in state.posix.dumps(1)

    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found = simgr.found[0]
        concrete_key = found.solver.eval(secret_key, cast_to=bytes)
        sys.stdout.buffer.write(concrete_key)
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
