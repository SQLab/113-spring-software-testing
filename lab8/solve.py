#!/usr/bin/env python3

import sys
import os

# --- 開始：診斷訊息 ---
print(f"solve.py DEBUG: 正在使用 Python 解譯器: {sys.executable}", file=sys.stderr)
print(f"solve.py DEBUG: Python 版本: {sys.version.splitlines()[0]}", file=sys.stderr)
print(f"solve.py DEBUG: 當前工作目錄: {os.getcwd()}", file=sys.stderr)
# --- 結束：診斷訊息 ---

import angr
import claripy
# import sys # sys 已經在上面導入過了
# import angr.options as so # <--- 移除或註解掉這一行

def main():
    # 1. 載入目標二進制檔案 'chal'
    try:
        proj = angr.Project("./chal", auto_load_libs=False)
    except angr.errors.AngrLoadError as e:
        print(f"錯誤：無法載入 './chal'。請確保它已被正確編譯。", file=sys.stderr)
        print(f"Angr 錯誤訊息：{e}", file=sys.stderr)
        sys.stdout.buffer.write(b"error_loading_binary_in_solve_py")
        sys.exit(1) 

    # 2. 設定初始狀態
    input_len = 8
    sym_input = claripy.BVS("sym_input_stdin", input_len * 8) 
    state = proj.factory.entry_state(stdin=sym_input)

    # --- 移除或註解掉以下關於 state.options 的程式碼 ---
    # state.options.add(so.ZERO_FILL_UNCONSTRAINED_MEMORY)
    # state.options.add(so.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    # --- --- --- --- --- --- --- --- --- --- --- ---

    # 3. 創建模擬管理器 (Simulation Manager)
    simgr = proj.factory.simgr(state)

    # 4. 執行符號執行探索
    print("solve.py: 開始符號執行 (不使用 angr.options)... 這可能需要一些時間。", file=sys.stderr)
    try:
        simgr.explore()
    except Exception as e:
        print(f"solve.py: 符號執行過程中發生錯誤：{e}", file=sys.stderr)
        sys.stdout.buffer.write(b"error_during_angr_explore")
        sys.exit(1)

    found_solution = False
    final_key = b"angr_did_not_find_solution_no_options" 

    # 5. 檢查 'deadended' stash 中的狀態尋找解決方案
    if simgr.deadended:
        print(f"solve.py: 發現 {len(simgr.deadended)} 個 deadended 狀態。正在檢查...", file=sys.stderr)
        for s in simgr.deadended:
            if s.satisfiable():
                try:
                    stdout_output = s.posix.dumps(1) 
                    if b"Correct! The flag is: CTF{symbolic_execution_for_the_win}" in stdout_output:
                        potential_key = s.solver.eval(sym_input, cast_to=bytes)
                        if len(potential_key) == input_len:
                            final_key = potential_key
                            found_solution = True
                            print(f"solve.py: 成功！找到解決方案狀態。金鑰: {final_key.decode('latin-1', errors='replace')}", file=sys.stderr)
                            print(f"solve.py: 此狀態的 Stdout: {stdout_output.decode('latin-1', errors='replace')}", file=sys.stderr)
                            break 
                        else:
                            print(f"solve.py: 警告：找到 'Correct!' 訊息，但金鑰長度為 {len(potential_key)}，預期為 {input_len}。金鑰: {potential_key}", file=sys.stderr)
                except angr.errors.SimSolverError as e_solver:
                    print(f"solve.py: 從 deadended 狀態求解時發生錯誤: {e_solver}", file=sys.stderr)
                except Exception as e_state_proc:
                    print(f"solve.py: 檢查 deadended 狀態時發生意外錯誤: {e_state_proc}", file=sys.stderr)
            else:
                print(f"solve.py: 發現一個不可滿足的 deadended 狀態，已跳過。歷史：{s.history.descriptions}", file=sys.stderr)
    else:
        print("solve.py: angr 未找到任何 deadended 狀態。", file=sys.stderr)

    if not found_solution and hasattr(simgr, 'found') and simgr.found:
        print(f"solve.py: 在 deadended 中未找到解。正在檢查 'found' stash (數量: {len(simgr.found)})...", file=sys.stderr)
        for s_found in simgr.found:
            if s_found.satisfiable():
                try:
                    stdout_output = s_found.posix.dumps(1)
                    if b"Correct!" in stdout_output:
                        potential_key = s_found.solver.eval(sym_input, cast_to=bytes)
                        if len(potential_key) == input_len:
                            final_key = potential_key
                            found_solution = True
                            print(f"solve.py: 成功！在 'found' stash 中找到解決方案。金鑰: {final_key.decode('latin-1', errors='replace')}", file=sys.stderr)
                            break
                except Exception as e_found_stash:
                    print(f"solve.py: 處理 'found' stash 中的狀態時發生錯誤: {e_found_stash}", file=sys.stderr)

    if not found_solution:
        print("solve.py: 在檢查所有相關狀態後未找到解決方案。", file=sys.stderr)
        if hasattr(simgr, 'errored') and simgr.errored:
            print(f"solve.py: 符號執行期間產生了 {len(simgr.errored)} 個錯誤狀態:", file=sys.stderr)
            for i, err_state in enumerate(simgr.errored):
                print(f"  錯誤 {i+1}: {err_state.error}", file=sys.stderr)

    print(f"solve.py: 最終寫入 stdout 的金鑰: {final_key}", file=sys.stderr)
    sys.stdout.buffer.write(final_key)

if __name__ == '__main__':
    try:
        main()
    except Exception as e_global:
        print(f"solve.py: main() 函數執行時發生未預期的全局錯誤: {e_global}", file=sys.stderr)
        sys.stdout.buffer.write(b"error_in_solve_py_main_execution")
        sys.exit(1)