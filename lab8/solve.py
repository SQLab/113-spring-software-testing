#!/usr/bin/env python3

import sys

import angr

angr.loggers.disable_root_logger()


def found_flag(state: angr.SimState):
    return b"flag" in state.posix.dumps(1)


def main():
    proj = angr.Project("./chal", auto_load_libs=False)
    state = proj.factory.entry_state(stdin=angr.SimFile)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=found_flag)
    if simgr.found:
        found_state = simgr.found[0]
        input_data = found_state.posix.dumps(0)
        sys.stdout.buffer.write(input_data)
    else:
        print("No solution found", file=sys.stderr)
        exit(1)


if __name__ == "__main__":
    main()
