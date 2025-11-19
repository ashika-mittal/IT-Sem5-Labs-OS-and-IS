import random
import time
p = 23
g = 5

start_gen = time.time()

a_private = random.randint(1, p-2)
a_public = pow(g, a_private, p)

b_private = random.randint(1, p-2)
b_public = pow(g, b_private, p)
end_gen = time.time()

start_exchange = time.time()

a_shared = pow(b_public, a_private, p)
b_shared = pow(a_public, b_private, p)
end_exchange = time.time()

print("Peer A Public Key:", a_public)
print("Peer B Public Key:", b_public)
print("Shared Secret A:", a_shared)
print("Shared Secret B:", b_shared)
print("Key Generation Time:", end_gen - start_gen)
print("Key Exchange Time:", end_exchange - start_exchange)
