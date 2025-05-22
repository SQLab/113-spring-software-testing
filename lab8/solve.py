#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # 1. 載入執行檔
    # auto_load_libs=False 可以加快速度，因為這個挑戰不需要共享函式庫的複雜互動
    project = angr.Project("./chal", auto_load_libs=False)

    # 2. 設定符號化輸入
    # chal.c 中的 gate 函式期望輸入長度為 8
    KEY_LEN = 8
    
    # 創建 KEY_LEN 個 8 位元的符號變數 (代表字元)
    sym_input_chars = [claripy.BVS(f'char_{i}', 8) for i in range(KEY_LEN)]
    # 將這些符號字元串接成一個大的位元向量
    sym_stdin_bvv = claripy.Concat(*sym_input_chars)

    # 3. 創建初始狀態
    # 將符號位元向量作為 stdin 傳遞給程式的入口點狀態
    # angr 的 SimProcedures 會模擬 fgets 從這個符號 stdin 中讀取數據
    initial_state = project.factory.entry_state(stdin=sym_stdin_bvv)

    # 4. (可選) 新增限制條件
    # 限制每個符號字元都在可列印 ASCII 範圍內 (32 到 126)
    # 這有助於 angr 更快找到有意義的解，並避免非預期的字元
    for char_sym in sym_input_chars:
        initial_state.solver.add(char_sym >= 32)  # 空格 ' '
        initial_state.solver.add(char_sym <= 126) # 波浪號 '~'

    # 5. 創建 SimulationManager
    simgr = project.factory.simulation_manager(initial_state)

    # 6. 探索路徑
    # 目標是找到一個狀態，其 stdout 包含 "Correct!"｀
    # 同時，我們可以避免那些明確打印 "Wrong key!" 的路徑 (雖然不是嚴格必要，但可能加快搜索)
    find_condition = lambda state: b"Correct!" in state.posix.dumps(1)
    avoid_condition = lambda state: b"Wrong key!" in state.posix.dumps(1)
    
    simgr.explore(find=find_condition, avoid=avoid_condition)

    secret_key_found = b""

    # 7. 檢查結果並解析金鑰
    if simgr.found:
        found_state = simgr.found[0]
        
        # 從找到的狀態中，解析出每個符號字元的具體值
        key_parts = []
        for i in range(KEY_LEN):
            key_parts.append(found_state.solver.eval(sym_input_chars[i], cast_to=bytes))
        
        secret_key_found = b"".join(key_parts)
        
        # (用於本地測試調試)
        # sys.stderr.buffer.write(b"Found secret key: " + secret_key_found + b"\n")
        
    else:
        # (用於本地測試調試)
        # sys.stderr.buffer.write(b"Could not find the secret key.\n")
        pass

    # 8. 將秘密金鑰寫入 stdout
    # validate.sh 會讀取這個 stdout
    sys.stdout.buffer.write(secret_key_found)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()