import sys
import angr
import claripy

def is_successful(state):
    stdout_output = state.posix.dumps(1)
    if b'Good Job.\n' in stdout_output:
        return True
    else:
        return False

def should_abort(state):
    stdout_output = state.posix.dumps(1)
    if b'Try again.\n' in stdout_output:
        return True
    else:
        return False

def Go():
    path_to_binary = "05_angr_symbolic_memory"
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x08048601
    initial_state = project.factory.blank_state(addr=start_address)

    passwd_size_bits = 64
    passwd0 = claripy.BVS('passwd0', passwd_size_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_bits)
    passwd2 = claripy.BVS('passwd2', passwd_size_bits)
    passwd3 = claripy.BVS('passwd3', passwd_size_bits)

    passwd0_address = 0x0A1BA1C0
    initial_state.memory.store(passwd0_address, passwd0)
    initial_state.memory.store(passwd0_address + 0x8, passwd1)
    initial_state.memory.store(passwd0_address + 0x10, passwd2)
    initial_state.memory.store(passwd0_address + 0x18, passwd3)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            s0 = solution_state.solver.eval(passwd0, cast_to=bytes)
            s1 = solution_state.solver.eval(passwd1, cast_to=bytes)
            s2 = solution_state.solver.eval(passwd2, cast_to=bytes)
            s3 = solution_state.solver.eval(passwd3, cast_to=bytes)
            output = s0 + b", " + s1 + b", " + s2 + b", " + s3
            print("[+] Success! Solution is : {}".format(output.decode("utf-8")))
    else:
        raise Exception("Could not found a solution")

if __name__ == "__main__":
    Go()

