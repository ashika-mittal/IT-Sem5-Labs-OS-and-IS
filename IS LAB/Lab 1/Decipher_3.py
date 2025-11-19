k = "GUIDANCE"
p = "The key is hidden under the door pad"
a = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

m = []
for c in (k + p).upper().replace('J', 'I'):
    if c in a and c not in m:
        m.append(c)
for c in a:
    if c not in m:
        m.append(c)
M = [m[i * 5:(i + 1) * 5] for i in range(5)]

t = "".join(c for c in p.upper() if c in a)

digraphs = []
i = 0
while i < len(t):
    a1 = t[i]
    if i + 1 == len(t):
        a2 = "X"
        i += 1
    else:
        a2 = t[i + 1]
        if a1 == a2:
            a2 = "X"
            i += 1
        else:
            i += 2
    digraphs.append(a1 + a2)

r = ""
for d in digraphs:
    a1, a2 = d[0], d[1]
    ra, ca = [(ix, iy) for ix, row in enumerate(M) for iy, v in enumerate(row) if v == a1][0]
    rb, cb = [(ix, iy) for ix, row in enumerate(M) for iy, v in enumerate(row) if v == a2][0]
    if ra == rb:
        r += M[ra][(ca + 1) % 5] + M[rb][(cb + 1) % 5]
    elif ca == cb:
        r += M[(ra + 1) % 5][ca] + M[(rb + 1) % 5][cb]
    else:
        r += M[ra][cb] + M[rb][ca]

print(r)
