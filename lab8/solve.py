#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # 1) 只載入自己編譯的 binary，不自動 load 其他動態庫
    proj = angr.Project('./chal', load_options={'auto_load_libs': False})

    # 2) 定義 8 個符號化的 8-bit 變數，對應 chal.c 中的 input[0]…input[7] :contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}
    key_chars = [claripy.BVS(f'k{i}', 8) for i in range(8)]
    key = claripy.Concat(*key_chars)

    # 3) 模擬 fgets() 讀到換行就停，但不當 EOF
    stdin_stream = angr.SimFileStream(
        name='stdin',
        content=key,
        has_end=False
    )

    # 4) 從 main() 開始執行，stdin 掛上我們的 SimFileStream
    state = proj.factory.entry_state(
        args=['./chal'],
        stdin=stdin_stream
    )
    # 用來避免一堆warning
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    # 5) 探索到標準輸出含 “Correct!” 的狀態即停止
    simgr = proj.factory.simgr(state)
    simgr.explore(
        find = lambda s: b"Correct!" in s.posix.dumps(1),
        avoid = lambda s: b"Wrong key!" in s.posix.dumps(1)
    )
    # 6) 若有找到，就把那組 key 解出來寫入 stdout（交給 chal 讀）
    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(key, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found.", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
