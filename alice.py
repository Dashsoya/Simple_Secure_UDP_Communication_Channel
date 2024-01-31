import socket
import random
import hashlib
import base64

P = 30387287447154679541028889864982585260179514055222254550054421295126275014939823371736558889451544502565400184934685074169514568960756102683571245787956754213248485026760855816313102493229452528544820829074228898328572798266032622201511632999419298618321215907212431559282301604639428883077538769962503372379620074389291828366553709362137010896356058216588460006167263113055883958693079956764173088786636833741475248349474216382088309952753294167301826462974090310040917134094350618323414478802384160616876169031718056279558719032677489325456923710039681947242914779981981898601579196507837389712412153895381323408781

G = 6

secret_alice = 1472816082441602010082713259779931884413475441084399524348704711930450054208760323741711283313194220053784023862829211267233839552733792035483362050086675925462112726038831957794663967346481699984888045912885590057756444923448260733797200500473830712459109390357366960546143624752399730122871837525869206264705720293805077246528661929568640397528753683874057671585191425984439608704300375453743695766526714714064505501754570939874773302412374932980875198098695603825799850751448842022925742621469515114211036086706245821656831086823353055204593015678516649605324232872402006730310288903208054726976788915851947743339

#Read in IP, Port, Keys
with open("alice.txt", 'r') as file:
    lines = [line.rstrip() for line in file.readlines()]

UDP_IP = lines[0]
UDP_PORT_SEND = int(lines[1])
UDP_PORT_RECEIVE = int(lines[3])
public_bob = int(lines[4])
public_alice = int(lines[5])

#UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT_RECEIVE))

while True:
    print()
    print()
    message = input("Alice: ")
    print()

    r = random.randint(2, P - 1)	#r (nonce) is chosen randomly
    first = pow(G, r, P)		#(G^r) mod P
    TK = pow(public_bob, r, P)		#TK = (bob_public_key^r) mod P
    #print("TK:")
    #print(TK)

    # Encrypt message using simple XOR operation
    encrypted_message_bytes = bytes([(ord(char) ^ TK) % 256 for char in message])
    encrypted_message = base64.b64encode(encrypted_message_bytes).decode('utf-8')

    LK = pow(public_bob, secret_alice, P)	#LK = ((bob_public_key)^(alice_secret_key)) mod P
    #print("LK:)
    #print(LK)

    # Compute MAC = H(LK || g^r || C || LK)
    mac_input = f"{LK}{first}{encrypted_message}{LK}"		#Concat all together
    mac = hashlib.sha256(mac_input.encode()).hexdigest()	#Get MAC

    # Display (g^r, C, MAC)
    print(f"Sending: {first},{encrypted_message},{mac}")	#G^r, C, MAC
    print()

    # Send the encrypted message and MAC
    combined_data = f"{first},{encrypted_message},{mac}"
    sock.sendto(combined_data.encode(), (UDP_IP, UDP_PORT_SEND))	#Sends G^r, C, MAC
    print("Waiting for message......")
    print()

    data, addr =sock.recvfrom(1024)		#Receive message from Bob
    print("Bob:", data.decode())
    print()

    received_data = data.decode()
    components = received_data.split(',')	#Split up G^r, C, MAC

    TK = pow(int(components[0]), secret_alice, P)	#TK = ((G^r)^alice_secret_key) mod P
    #print("TK:")
    #print(TK)

    LK = pow(public_bob, secret_alice, P)		#LK = ((bob_public_key)^(alice_secret_key)) mod P
    #print("LK:")
    #print(LK)

    mac_input = f"{LK}{components[0]}{components[1]}{LK}"	#Concat all together
    mac = hashlib.sha256(mac_input.encode()).hexdigest()	#Get MAC

    if mac == components[2]:					#Compares MAC that Alice calculated sent VS MAC that Bob sent
        encrypted_message_bytes = base64.b64decode(components[1])	#Decrypt the message using TK if MAC matches
        decrypted_message = ''.join([chr((byte ^ TK) % 256) for byte in encrypted_message_bytes])

        print(f"Decrypted Message: {decrypted_message}")
