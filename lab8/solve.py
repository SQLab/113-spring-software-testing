import angr
import sys
import claripy

angr.loggers.disable_root_logger()

def main():
    proj = angr.Project("chal", auto_load_libs=False)
    flag_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]
    flag = claripy.Concat(*flag_bytes)

    state = proj.factory.full_init_state(
        stdin = angr.SimFileStream(name='stdin', content=flag, has_end=True)
    )

    simgr = proj.factory.simulation_manager(state)
    
    simgr.explore(find=lambda s: b"flag" in s.posix.dumps(1))

    if len(simgr.found) > 0:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        sys.stdout.buffer.write(solution)
    else:
        print("No solution found")

if __name__ == '__main__':
    main()
