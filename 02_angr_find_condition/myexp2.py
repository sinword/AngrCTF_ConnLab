import angr
import sys

def Go():
    path_to_binary = "./02_angr_find_condition"
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    def good_job(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        if b'Good Job.' in stdout_output:
            return True
        else:
            return False

    def try_again(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        if b'Try again.' in stdout_output:
            return True
        else:
            return False
    
    simulation.explore(find=good_job, avoid=try_again)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
    else:
        raise Exception("Could not find the solution")

if __name__ == "__main__":
    Go()
