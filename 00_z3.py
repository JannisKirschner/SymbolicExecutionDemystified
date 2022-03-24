from z3 import *

a1 = [BitVec(f'{i}', 8) for i in range(0x19)]
s = Solver()

s.add((a1[20] ^ 0x2B) == a1[7])
s.add(a1[21] - a1[3] == -20)
s.add((a1[2] >> 6) == 0)
s.add(a1[13] == 116)
s.add(4 * a1[11] == 380)
s.add(a1[7] >> (a1[17] % 8) == 5)
...

print(s.check())
model = s.model()
flag = ''.join([chr(int(str(model[a1[i]]))) for i in range(len(model))])
print(flag)
