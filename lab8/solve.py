#!/usr/bin/env python3

import angr,sys

def main():
    secret_key = b"no answer here"
    sys.stdout.buffer.write(secret_key)


if __name__ == '__main__':
    main()
