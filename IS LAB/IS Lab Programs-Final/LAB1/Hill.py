import numpy as np
from Crypto.Util.number import inverse

def text_to_nums(s):
    return [ord(c) - 65 for c in s.upper() if c.isalpha()]

def nums_to_text(nums):
    return ''.join(chr(n % 26 + 65) for n in nums)

def chunk_pairs(nums):
    return [nums[i:i+2] for i in range(0, len(nums), 2)]

K = np.array([[3, 3],
              [2, 7]])

MOD = 26

def hill_encrypt(plaintext, K):
    nums = text_to_nums(plaintext)
    # pad with 'X' if odd length
    if len(nums) % 2 == 1:
        nums.append(ord('X') - 65)
    cipher_nums = []
    for pair in chunk_pairs(nums):
        vec = np.array(pair)
        result = np.dot(K, vec) % MOD
        cipher_nums.extend(result)
    return nums_to_text(cipher_nums)

def modinv(a, m):
    return inverse(int(a), m)

def matrix_det_2x2(M):
    return int((M[0,0]*M[1,1] - M[0,1]*M[1,0]) % MOD)

def matrix_inverse_2x2(M):
    det = matrix_det_2x2(M)
    inv_det = modinv(det, MOD)
    # inverse = inv_det * [ d -b; -c a ] (mod MOD)
    adj = np.array([[M[1,1], -M[0,1]],
                    [-M[1,0], M[0,0]]])
    return (inv_det * adj) % MOD

def hill_decrypt(ciphertext, K):
    nums = text_to_nums(ciphertext)
    if len(nums) % 2 == 1:
        raise ValueError("Ciphertext length must be even for 2x2 Hill")
    K_inv = matrix_inverse_2x2(K)
    plain_nums = []
    for pair in chunk_pairs(nums):
        vec = np.array(pair)
        result = np.dot(K_inv, vec) % MOD
        plain_nums.extend(result)
    return nums_to_text(plain_nums)

# ----------------- Run the example -----------------
message = "We live in an insecure world"
cipher = hill_encrypt(message, K)
plaintext_recovered = hill_decrypt(cipher, K)

print("Plaintext (processed):", "".join([c for c in message.upper() if c.isalpha()]))
print("Ciphertext:", cipher)
print("Decrypted (recovered):", plaintext_recovered)
