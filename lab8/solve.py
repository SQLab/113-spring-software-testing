#!/usr/bin/env python3

import sys

import angr
import claripy

PROJECT_PATH = "./chal"


def answer(key):
    sys.stdout.buffer.write(key)


def success(state):
    return b"Correct" in state.posix.dumps(1)


def failure(state):
    return b"Wrong" in state.posix.dumps(1)


def main():
    project = angr.Project(PROJECT_PATH, auto_load_libs=False)

    input = claripy.BVS("input", 64)  # 8 bytes

    state = project.factory.full_init_state(stdin=input)

    for byte in input.chop(8):
        # answer should be printable ascii, 0x20 ~ 0x7E
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7E)

    simgr = project.factory.simgr(state)

    simgr.explore(find=success, avoid=failure)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(input, cast_to=bytes)
        answer(solution)
    else:
        raise Exception("AnswerNotFoundError")


if __name__ == "__main__":
    main()
