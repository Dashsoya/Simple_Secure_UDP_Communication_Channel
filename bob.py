import socket
import random
import hashlib
import base64

P =30387287447154679541028889864982585260179514055222254550054421295126275014939823371736558889451544502565400184934685074169514568960756102683571245787956754213248485026760855816313102493229452528544820829074228898328572798266032622201511632999419298618321215907212431559282301604639428883077538769962503372379620074389291828366553709362137010896356058216588460006167263113055883958693079956764173088786636833741475248349474216382088309952753294167301826462974090310040917134094350618323414478802384160616876169031718056279558719032677489325456923710039681947242914779981981898601579196507837389712412153895381323408781

G = 6

secret_bob = 18359838778651256054963972403577385836774993081779519981867005093166649905521673461583626275727661298952686098518497624833013547672647745016091354780490065146085164971163053329956192489879776298100196439982361269937331870865900600798561905138837631268970577886079046981250519470743279668954001859947737557358723514676010607744585789380427400626917043328972895346701320074189856536499613758732297381360293214248331953510809286535071923412157106352799472811551388908133446591851978878427667059975408230840428168265270080415530697177245190327212085240282799683273293246402729721047002777922016641218753024031461710676037

#Read in IP, Port, Keys
with open("bob.txt", 'r') as file:
    lines = [line.rstrip() for line in file.readlines()]

UDP_IP = lines[0]
UDP_PORT_SEND = int(lines[1])
UDP_PORT_RECEIVE = int(lines[3])
public_alice = int(lines[4])
public_bob = int(lines[5])

#UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
sock.bind((UDP_IP, UDP_PORT_RECEIVE))

while True:
    print()
    data, addr = sock.recvfrom(1024)  #Receive message from Alice
    print("Alice:", data.decode())
    print()

    received_data = data.decode()
    components = received_data.split(',')	#Split up G^r, C, MAC

    TK = pow(int(components[0]), secret_bob, P)	#TK = ((G^r)^bob_secret_key) mod P
    #print("TK:")
    #print(TK)

    LK = pow(public_alice, secret_bob, P)  	#LK = ((alice_public_key)^(bob_secret_key)) mod P
    #print("LK:")
    #print(LK)

    mac_input = f"{LK}{components[0]}{components[1]}{LK}"	#Concat all together
    mac = hashlib.sha256(mac_input.encode()).hexdigest()	#Get MAC 

    if mac == components[2]:					#Compares MAC that Bob calculated vs MAC that Alice sent
        encrypted_message_bytes = base64.b64decode(components[1])	#Decrypt the message using TK if MAC matches
        decrypted_message = ''.join([chr((byte ^ TK) % 256) for byte in encrypted_message_bytes])

        print(f"Decrypted Message: {decrypted_message}")

    print()
    print()
    message = input("Bob: ")		#Bob's turn to send message
    print()

    r = random.randint(2, P - 1)	#r (nonce) is chosen randomly
    first = pow(G, r, P)		#(G^r) mod P
    TK = pow(public_alice, r, P)	#TK = (alice_public_key^r) mod P
    #print("TK")
    #print(TK)

    #Encrypt message using simple XOR operation
    encrypted_message_bytes = bytes([(ord(char) ^ TK) % 256 for char in message])
    encrypted_message = base64.b64encode(encrypted_message_bytes).decode('utf-8')

    LK = pow(public_alice, secret_bob, P)	#LK = ((alice_public_key)^(bob_secret_key)) mod P
    #print("LK: ")
    #print(LK)

    #Compute MAC = H(LK || g^r || C || LK)	
    mac_input = f"{LK}{first}{encrypted_message}{LK}"	#Concat all together
    mac = hashlib.sha256(mac_input.encode()).hexdigest()	#Get MAC

    # Display (g^r, C, MAC)
    print(f"Sending: {first},{encrypted_message},{mac}")	#G^r, C, MAC
    print()

    # Send the encrypted message and MAC
    combined_data = f"{first},{encrypted_message},{mac}"	
    sock.sendto(combined_data.encode(), (UDP_IP, UDP_PORT_SEND))	#Sends G^r, C, MAC
    print("Waiting for message......")	
    print()
