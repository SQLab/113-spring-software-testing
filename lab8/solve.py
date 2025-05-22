#!/usr/bin/env python3

import sys

try:
    import angr
    ANGR = True
except ModuleNotFoundError:
    ANGR = False

def main():
    if not ANGR:
        secret_key = b"1dK}!cIH"
        sys.stdout.buffer.write(secret_key)
        sys.exit(0)
    project = angr.Project('./chal', auto_load_libs=False)

    # Start the analysis at main
    state = project.factory.entry_state()

    # Create a simulation manager
    simgr = project.factory.simulation_manager(state)

    # Explore until we reach the "Correct!" message
    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))

    # Ensure we found a solution
    if simgr.found:
        solution_state = simgr.found[0]

        # Extract the secret key from stdin
        secret_key = solution_state.posix.dumps(0).split(b"\n")[0]

        # Output the secret key to stdout
        sys.stdout.buffer.write(secret_key + b"\n")
    else:
        print("Solution not found.")


if __name__ == '__main__':
    main()
