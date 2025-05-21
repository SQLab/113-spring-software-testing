import angr
import sys

def main():
    angr.loggers.disable_root_logger()

    proj = angr.Project("chal")
    state = proj.factory.entry_state(stdin=angr.SimFile)
    simgr = proj.factory.simulation_manager(state)
    
    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1),
                 avoid=lambda s: b"Wrong key!" in s.posix.dumps(1))

    if len(simgr.found) > 0:
        found_state = simgr.found[0]
        solution = found_state.posix.dumps(0)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found")

if __name__ == '__main__':
    main()