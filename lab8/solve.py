#!/usr/bin/env python3

def solve():
    # 我們需要找到滿足以下條件的 8 個字元：
    # 1. (input[0] ^ input[1]) == 0x55
    # 2. (input[2] + input[3]) == 200
    # 3. (input[4] * 3) == input[5]
    # 4. (input[6] - input[7]) == 1
    # 5. (input[1] + input[2] - input[3]) == 50
    # 6. (input[5] ^ input[6]) == 0x2A
    
    # 嘗試所有可能的值
    for a in range(32, 127):  # input[0]
        for b in range(32, 127):  # input[1]
            if (a ^ b) != 0x55:
                continue
                
            for c in range(32, 127):  # input[2]
                for d in range(32, 127):  # input[3]
                    if (c + d) != 200:
                        continue
                    
                    if (b + c - d) != 50:
                        continue
                    
                    for e in range(32, 127):  # input[4]
                        f = e * 3  # input[5]
                        if f < 32 or f > 126:
                            continue
                            
                        for g in range(32, 127):  # input[6]
                            if (f ^ g) != 0x2A:
                                continue
                                
                            h = g - 1  # input[7]
                            if h < 32 or h > 126:
                                continue
                            
                            # 所有條件都滿足，輸出密鑰
                            key = chr(a) + chr(b) + chr(c) + chr(d) + chr(e) + chr(f) + chr(g) + chr(h)
                            return key
    
    return "No solution found!"

if __name__ == "__main__":
    key = solve()
    print(key)
