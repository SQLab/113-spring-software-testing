import sys
import angr

def found_correct(state: angr.SimState):
    return b"Correct!" in state.posix.dumps(1)

def avoid_wrong(state: angr.SimState):
    return b"Wrong key!" in state.posix.dumps(1)

def main():
    angr.loggers.disable_root_logger()

    proj = angr.Project("./chal", auto_load_libs=False)
    state = proj.factory.entry_state(stdin=angr.SimFile)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=found_correct, avoid=avoid_wrong)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.posix.dumps(0)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found", file=sys.stderr)
        exit(1)

if __name__ == "__main__":
    main()
