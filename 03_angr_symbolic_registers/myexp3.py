import sys
import angr
import claripy

def is_successful(state):
    if b"Good Job." in state.posix.dumps(sys.stdout.fileno()):
        return True
    else:
        return False

def should_abort(state):
    if b"Try again" in state.posix.dumps(sys.stdout.fileno()):
        return True
    else:
        return False

def Go():
    path_to_binary = "./03_angr_symbolic_registers"
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x0804897
    initial_state = project.factory.blank_state(addr=start_address)

    initial_state.regs.ebp = initial_state_regs.esp
    padding_length_in_bytes = 0x12
    initial_state.regs.esp -= padding_length_in_bytes

    passwd_size_in_bits = 32
    passwd0 = claripy.BVS("passwd0", passwd_size_in_bits)
    passwd1 = claripy.BVS("passwd1", passwd_size_in_bits)
    passwd2 = claripy.BVS("passwd2", passwd_size_in_bits)

    initial_state.stack_push(passwd0)
    initial_state.stack_push(passwd1)
    initial_state.stach_push(passwd2)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution0 = format(solution_state.solver.eval(passwd0), 'x')
            solution1 = format(solution_state.solver.eval(passwd1), 'x')
            solution2 = format(solution_state.solver.eval(passwd2), 'x')
            solution = solution0 + " " + solution1 + " " + solution2
            print("[+] Success! Solution is: {}".format(solution))
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
