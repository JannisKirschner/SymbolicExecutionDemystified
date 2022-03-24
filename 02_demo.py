import angr
import claripy

def visualize(*args, **kwargs):
	stashes = args[0].stashes
	for simstate in stashes["active"]:
		print(simstate.posix.dumps(0))

print("[*] Welcome to angr solution script")
proj = angr.Project('crackme')
simgr = proj.factory.simgr()
print("[*] Starting to explore target binary")
simgr.explore(find=lambda s: b"Solved" in s.posix.dumps(1), step_func=visualize)
s = simgr.found[0]
print("\n----------\n[+] Solution found: {}\n----------".format(s.posix.dumps(0).decode("utf-8")))
