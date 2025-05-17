#!/usr/bin/env python3
import sys

def main():
    sol = None

    for b3 in range(91, 127):
        b2 = 200 - b3
        b1 = 2 * b3 - 150
        if not (0x20 <= b1 <= 0x7e):
            continue
        b0 = b1 ^ 0x55
        if not (0x20 <= b0 <= 0x7e):
            continue

        for b4 in range(0x20, 43):
            b5 = 3 * b4
            if not (0x20 <= b5 <= 0x7e):
                continue

            b6 = b5 ^ 0x2A
            b7 = b6 - 1
            if not (0x20 <= b6 <= 0x7e and 0x20 <= b7 <= 0x7e):
                continue

            if not (b2 + b3 == 200): continue
            if not (b1 + b2 - b3 == 50): continue
            if not (b6 - b7 == 1): continue

            sol = [b0, b1, b2, b3, b4, b5, b6, b7]
            break
        if sol is not None:
            break

    if sol is None:
        sys.exit(1)

    data = bytes(sol)
    sys.stdout.buffer.write(data)

if __name__ == "__main__":
    main()
