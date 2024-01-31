from Crypto.Util.number import getPrime, getRandomRange

# Generate a 2048-bit prime number
P = getPrime(2048)
print("Prime Number P:", P)
print("")

# Find a primitive root of P
G = 2  # Start with a candidate (eg 2)
while G == 2 or pow(G, (P - 1) // 2, P) == 1:
    G += 1

print("Primitive Root G:", G)
print("")


secret_key_alice = getRandomRange(1, P-1)
print("Secret Key (Alice):", secret_key_alice)
print("")
secret_key_bob = getRandomRange(1, P-1)
print("Secret Key (Bob):", secret_key_bob)
print("")

public_key_alice = pow(G, secret_key_alice, P)  
print("Public Key (Alice):", public_key_alice)
print("")
public_key_bob = pow(G, secret_key_bob, P)  
print("Public Key (Bob):", public_key_bob)
print("")



