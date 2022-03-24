import angr
import claripy
import uuid

proj = angr.Project("./z3_robot",load_options={"auto_load_libs": False},
                    main_opts={"base_addr": 0})
flag = [claripy.BVS(f"c_{i}", 8) for i in range(0x19)]
flag_ast = claripy.Concat(*flag)
state = proj.factory.entry_state(stdin=flag_ast)
for f in flag:
    state.solver.add(f >= 0x20)
    state.solver.add(f < 0x7f)

print(state.history.bbl_addrs.hardcopy)

simgr = proj.factory.simulation_manager(state)
print("Exploration Started...")

#simstate from simgr -> history
def get_small_coverage(*args, **kwargs):
    sm = args[0]

    stashes = sm.stashes

    i = 0
    for simstate in stashes["active"]:
        state_history = ""
        for addr in simstate.history.bbl_addrs.hardcopy:
            write_address = hex(addr)
            state_history += "{0}\n".format(write_address)
        #posix.dumps(fd) also works
        raw_syminput = simstate.posix.stdin.load(0, state.posix.stdin.size)
        syminput = simstate.solver.eval(raw_syminput, cast_to=bytes)
        print(syminput)
        instruction_pointer = hex(state.solver.eval(simstate.ip))
        filename = "{0}_active_{1}_{2}_{3}".format(str(i).zfill(5),syminput, instruction_pointer, str(uuid.uuid4()))
        with open(filename, "w") as f:
            f.write(state_history)
        i += 1


def get_full_coverage(*args, **kwargs):
    sm = args[0]

    stashes = sm.stashes

    for category in stashes:
        for simstate in stashes[category]:
            i = 0
            for simstate in stashes[category]:
                state_history = ""
                for addr in simstate.history.bbl_addrs.hardcopy:
                    write_address = hex(addr)
                    state_history += "{0}\n".format(write_address)
                raw_syminput = simstate.posix.stdin.load(0, state.posix.stdin.size)
                syminput = simstate.solver.eval(raw_syminput, cast_to=bytes)
                instruction_pointer = hex(state.solver.eval(simstate.ip))
                filename = "{0}_{1}_{2}_{3}_{4}".format(str(i).zfill(5),syminput,category,instruction_pointer, str(uuid.uuid4()))
                with open(filename, "w") as f:
                    f.write(state_history)
                i += 1



simgr.explore(find=lambda s: b"Well" in s.posix.dumps(1), step_func=get_small_coverage)


if len(simgr.found) > 0:
    found = simgr.found[0]

    valid_flag = found.solver.eval(flag_ast, cast_to=bytes)
    print(valid_flag)

    state_history = ""
    for addr in found.history.bbl_addrs.hardcopy:
        write_address = hex(addr)
        state_history += "{0}\n".format(write_address)
    with open("SATISFIABLE_{0}".format(valid_flag), "w") as f:
        f.write(state_history)

else:
    print("UNSATISFIABLE")
