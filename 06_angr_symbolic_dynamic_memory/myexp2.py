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
    path_to_binary = "./06_angr_symbolic_dynamic_memory"
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x08048699
    initial_state = project.factory.blank_state(addr=start_address)

    passwd_size_in_bits = 64
    passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)

    fake_heap_address0 = 0xffffc93c
    pointer_to_malloc_memory_address0 = 0xabcc8a4
    fake_heap_address1 = 0xffffc94c
    pointer_to_malloc_memory_address1 = 0xabcc8ac
    initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
    initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

    initial_state.memory.store(fake_heap_address0, passwd0)
    initial_state.memory.store(fake_heap_address1, passwd1)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            s0 = solution_state.solver.eval(passwd0, cast_to=bytes)
            s1 = solution_state.solver.eval(passwd1, cast_to=bytes)
            output = s0 + b", " + s1
            print("[+] Success! Solution is {}".format(output.decode("utf-8")))
    else:
        raise Exception("Could not find the solution")

if __name__ == "__main__":
    Go()
