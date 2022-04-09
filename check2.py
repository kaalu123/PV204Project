import tss
import socket
from tss import share_secret, Hash
import base64
import sys
from Crypto.Cipher import AES
from binascii import unhexlify
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asymmetric, rsa, utils
from cryptography.hazmat.primitives import padding as padding_symmetric, hashes, serialization
import binascii
import os
import datetime
import time
from tqdm import tqdm
from subprocess import call
import hashlib

pwd=os.getcwd()
#client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

salt = b'001122334455667788'
IP = socket.gethostbyname(socket.gethostname())
PORT = 4456
ADDR = (IP, PORT)
SIZE = 10240
FORMAT = "utf-8"
FILENAME = "clear.txt"
if(os.path.isfile(FILENAME)== False):
    print("No source file clear.txt present to encrypt and hide using the secret.Please create clear.txt. Exiting .....")
    exit(0)
            

FILESIZE = os.path.getsize(FILENAME)

# Creating a TCP server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#start_server()

    
server.setblocking(False)
server.bind(ADDR)
server.listen()
print("[+] Listening...")



# Generating keypair and certificate of a notional CA who will sign public certificates of legitimate users of the sharing scheme.
def CA_key_cert_gen():
    CA_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Write our key to disk for safe keeping

    with open("CA-key.pem", "wb") as f:
        f.write(CA_key.private_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PrivateFormat.TraditionalOpenSSL,

            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),

        ))
    print("Generated Keypair for CA.........................")
    #time.sleep(2)

    print("Generating Self Signed Certificate for CA.........................")
    #time.sleep(2)
    subject = issuer = x509.Name([

        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CZ"),

        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Brno"),

        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Masaryk University"),

        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Informatics"),

        x509.NameAttribute(NameOID.COMMON_NAME, u"CA.com"),

    ])

    CA_cert = x509.CertificateBuilder().subject_name(

        subject

    ).issuer_name(

        issuer

    ).public_key(

        CA_key.public_key()

    ).serial_number(

        x509.random_serial_number()

    ).not_valid_before(

        datetime.datetime.utcnow()

    ).not_valid_after(

        # Our certificate will be valid for 10 days

        datetime.datetime.utcnow() + datetime.timedelta(days=10)

    ).add_extension(

        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),

        critical=False,

        # Sign our certificate with our private key

    ).sign(CA_key, hashes.SHA256())

    # Write our certificate out to disk.

    with open("CA-cert.pem", "wb") as f:
        f.write(CA_cert.public_bytes(serialization.Encoding.PEM))


# Generating keypairs and certificates for all users part of our multi party system
def RSA_users_key_cert_gen(s,t):  # Usage of classess of cryptography library referenced from https://cryptography.io/en/latest/
    for x in range(1, s + 1):
        user_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        # Write our key to disk for safe keeping
        
        dir_key= f"{pwd}/User{x}/User{x}-key.pem"
        os.makedirs(os.path.dirname(dir_key), exist_ok=True)
        with open(dir_key, "wb") as f:
            f.write(user_key.private_bytes(

                encoding=serialization.Encoding.PEM,

                format=serialization.PrivateFormat.TraditionalOpenSSL,

                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),

            ))
        print(f"Generated Keypair for User {x}.........................")
        #time.sleep(2)
        # Generate a CSR for a user
        print(f"Generating Certificate Signing Request for User {x}.........................")
        #time.sleep(2)
        user_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

            # Provide various details about user is.

            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CZ"),

            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Brno"),

            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Brno Mesto"),

            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MUNI"),

            x509.NameAttribute(NameOID.COMMON_NAME, f"User-{x}.com"),

        ])).add_extension(

            x509.SubjectAlternativeName([

                # Describe what sites we want this certificate for.

                x509.DNSName(f"User-{x}.com"),

                x509.DNSName(f"www.User-{x}.com"),

                x509.DNSName(f"subdomain.User-{x}.com"),

            ]),

            critical=False,

            # Sign the CSR with our private key.

        ).sign(user_key, hashes.SHA256())

        # Write our CSR out to disk.
        dir_csr= f"{pwd}/User{x}/User{x}-csr.pem"
        #os.makedirs(os.path.dirname(dir_csr), exist_ok=True)
        with open(dir_csr, "wb") as f:
            f.write(user_csr.public_bytes(serialization.Encoding.PEM))
        
        dir_crt= f"{pwd}/User{x}/User{x}-cert.pem"
        print("Generating Certificate for User signed by CA.........................")
        #time.sleep(2)
        f1 = open(dir_csr, "rb")
        data1 = f1.read()
        user_csr = x509.load_pem_x509_csr(data1)
        isinstance(user_csr.signature_hash_algorithm, hashes.SHA256)

        f3 = open("CA-cert.pem", "rb")
        data3 = f3.read()
        CA_cert = x509.load_pem_x509_certificate(data3)  # Loading CA's certificate

        with open("CA-key.pem", "rb") as f4:
            CA_key = serialization.load_pem_private_key(
                f4.read(),
                password=b"passphrase",
            )

        user_cert = x509.CertificateBuilder().subject_name(
            user_csr.subject
        ).issuer_name(
            CA_cert.subject
        ).public_key(
            user_csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
            # Sign our certificate with our private key
        ).sign(CA_key, hashes.SHA256())

        with open(dir_crt, "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))


# derive
def key_from_secret(secret):
    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=390000,

    )

    key = kdf.derive(bytes(secret, 'utf-8'))

    # verify

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=390000,

    )

    kdf.verify(bytes(secret, 'utf-8'), key)
    print("Derived the key from the secret for encrypting our source file")
    #time.sleep(2)
    return key


def create_shares(t, s, secret):
    shares = tss.share_secret(t, s, secret, 'my-id', Hash.NONE)
    #print("Secret:\t", secret)
    print("===Initial Shares are as below which will be encrypted and thereafter plaintext of shares will never be available after creation\n")
    #time.sleep(2)
    for x in range(0, s):
        print(base64.b64encode(shares[x]))
        
    #print(type(shares))
    return shares


def distribute_shares(s,shares):
    CA_cert_file = open("CA-cert.pem", "rb")
    CA_mid_cert = CA_cert_file.read()
    CA_cert = x509.load_pem_x509_certificate(CA_mid_cert)
    CA_public_key = CA_cert.public_key()
    print("Starting distribution of shares to users after authenticating their certificates and sending each user his share encrypted by his public key")
    #time.sleep(2)
    for x in range(1, s+1):
        
        # Loading User's Certificate for verification
        dir_crt= f"{pwd}/User{x}/User{x}-cert.pem"
        user_cert_file = open(dir_crt, "rb")
        user_mid_cert = user_cert_file.read()
        user_cert = x509.load_pem_x509_certificate(user_mid_cert)
        user_public_key = user_cert.public_key()
        verif = CA_public_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        print(f"User {x} Certificate verified")
        #time.sleep(2)
        # Now encrypt each share using the public key of specific user.
        ciphertext = user_public_key.encrypt(  # Encrypting the share with User's Public Key
            shares[x-1],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Also the Dealer signs all these shares using his private key so that dishonest clients cannot produce their own invalid shares during reconstruction.
        with open("CA-key.pem","rb") as in_key:
            pem_data=in_key.read()
            CA_private_key = serialization.load_pem_private_key(pem_data, password=b"passphrase")
            
        signed_data= rsa_sign_pss_sha256(CA_private_key,ciphertext)
        
        # Now write each encrypted share with signature in a file for giving security to the share
        with open(f"signed_enc_share_user{x}.txt","wb") as out:
            out.write(ciphertext+signed_data)
            #print(f"Check{x}")

        # Verify the signature of each encrypted share of the user to ensure each party produces honest shares.    
        # Now send these signed and encrypted shares to these clients.
        dir_signed_enc_share=f"{pwd}/User{x}/signed_enc_share_user{x}.txt"
        FILENAME = f"signed_enc_share_user{x}.txt"
        FILESIZE = os.path.getsize(FILENAME)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        """ Accepting the connection from the client. """
        conn, addr = server.accept()
        print(f"[+] Client(User{x}) connected from {addr[0]}:{addr[1]}")
            
        """ Sending the filename and filesize to the client. """
        data_client = f"{FILENAME}@{FILESIZE}"
        client.setblocking(False)
        conn.setblocking(False)
        conn.send(data_client.encode(FORMAT))
            
        """ Receiving the filename and filesize from the server. """
        data_server = client.recv(SIZE).decode(FORMAT)
        item = data_server.split("@")
        print(item)
        FILESIZE = int(item[1])

        print("[+] Filename and filesize received from the server.")
        client.send("Filename and filesize received".encode(FORMAT))
        msg = conn.recv(SIZE).decode(FORMAT)
            
        print(f"Client{x}: {msg}")
    
        """ Data transfer. """
        print(FILENAME)
        f=open(FILENAME,"rb")
        data_client=f.read()
        conn.send(data_client)
        data_server = client.recv(SIZE)
        f1=open(dir_signed_enc_share,"wb")
        f1.write(data_server)
        f.close()
        f1.close()
        
        # Each client will verify the signature on the shares before accepting otherwise reject the share.
        
        f=open(dir_signed_enc_share,"rb")
        f.seek(-512, 2)
        recv_signed_data=f.read()
        f.seek(0)
        recv_ciphertext=f.read(512)
        sign_verif=rsa_verify_pss_sha256(CA_public_key,recv_ciphertext,recv_signed_data)
        if(sign_verif==False):
            print(f"Signature verification of encrypted share failed for user{x}")
        else:
            print(f"Signature on the encrypted share verified for user{x}")
        
        f.close()
        
        # Remove the encrypted shares and signatures from the server after successfull distribution of shares
        os.remove(f"signed_enc_share_user{x}.txt")
            
        
        
        """ Closing the connection """
        client.close()

        """ Closing connection. """
        conn.close()
                
        '''except:
            print("Invalid Certificate")
            #exit(0)		#Exit communication if parties not authenticated'''

def rsa_sign_pss_sha256(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Use RSA `private_key` to digitally sign of `data`.

    :param private_key: RSA private key
    :param data: the data to be signed

    :return: the bytes of the signature

    Example:

    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> signature = rsa_sign_pss_sha256(private_key=private_key, data=b"a contract contents")
    """
    prehashed_msg = hashlib.sha256(data).digest()
    signature = private_key.sign(
        prehashed_msg,
        padding_asymmetric.PSS(
            mgf=padding_asymmetric.MGF1(hashes.SHA256()),
            salt_length=padding_asymmetric.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )
    return signature

def rsa_verify_pss_sha256(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify that the `signature` of `data` was signed using the RSAPrivateKey
    corresponding to `public_key`.

    :param public_key: the RSAPublicKey to be used for the verification
    :param data: the data that were signed
    :param signature: the bytes of the signature

    Example:

    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> data = b"the contract contents"
    >>> signature = rsa_sign_pss_sha256(private_key=private_key, data=data)
    >>> assert rsa_verify_pss_sha256(public_key=public_key, data=data, signature=signature)
    """
    prehashed_msg = hashlib.sha256(data).digest()
    try:
        public_key.verify(
            signature,
            prehashed_msg,
            padding_asymmetric.PSS(
                mgf=padding_asymmetric.MGF1(hashes.SHA256()),
                salt_length=padding_asymmetric.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return True
    except:
        return False



def recollect_shares(t):
    # Validate Dealer/server's certificate before sending decrypted share
    CA_cert_file = open("CA-cert.pem", "rb")
    CA_mid_cert = CA_cert_file.read()
    CA_cert = x509.load_pem_x509_certificate(CA_mid_cert)
    CA_public_key = CA_cert.public_key()
    verif = CA_public_key.verify(
        CA_cert.signature,
        CA_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        CA_cert.signature_hash_algorithm
    )
    print(f"Dealer/Server Certificate verified")
    
    
    
    
    print("Recollecting shares from T(Threshold) no of users for reconstructing the secret after validating their certificates")
    #time.sleep(2)
    for x in range(1,t+1):
        dir_key= f"{pwd}/User{x}/User{x}-key.pem"
        dir_csr= f"{pwd}/User{x}/User{x}-csr.pem"
        dir_crt= f"{pwd}/User{x}/User{x}-cert.pem"
        dir_signed_enc_share=f"{pwd}/User{x}/signed_enc_share_user{x}.txt"
        dir_dec_share=f"{pwd}/User{x}/dec_share_user{x}.txt"
        dir_signed_share=f"{pwd}/User{x}/signed_enc_share_user{x}.txt"
        
        # Decrypt the encrypted shares present with each user and further encrypt with the public key of dealer and sign with own private key before sending to server.
        with open(dir_signed_share,"rb") as in_file:
            decr_share=in_file.read(512)
        # Now decrypt each share using the private key of specific user.(This key only available to the user himself as depicted by a seperate directory in this program)
        with open(dir_key,"rb") as in_key:
            pem_data=in_key.read()
            user_private_key = serialization.load_pem_private_key(pem_data, password=b"passphrase")
        plain_share = user_private_key.decrypt(
            decr_share,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )    
        # Now as the shares cannot be passed unencrypted in the network, re encrypt it with dealer's public key
        send_share = CA_public_key.encrypt(  
            plain_share,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Also compute the signature for this payload and append
        signed_send_share= rsa_sign_pss_sha256(user_private_key, send_share)
        # Now write each encrypted share to be recollected with signature in a file for giving security to the share
        dir_recollected_share=f"{pwd}/User{x}/recollected_share_user{x}.txt"
        with open(dir_recollected_share,"wb") as out:
            out.write(send_share + signed_send_share)
        
        
            
        # Send the shares back to the server for recomputation of secret.
        
        FILESIZE = os.path.getsize(dir_recollected_share)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        """ Accepting the connection from the client. """
        conn, addr = server.accept()
        print(f"[+] Client(User{x}) connected from {addr[0]}:{addr[1]}")
            
        """ Sending the filename and filesize to the server. """
        data_client = f"{dir_recollected_share}@{FILESIZE}"
        client.setblocking(False)
        conn.setblocking(False)
        client.send(data_client.encode(FORMAT))
            
        """ Receiving the filename and filesize from the client. """
        data_server = conn.recv(SIZE).decode(FORMAT)
        item = data_server.split("@")
        print(item)
        FILESIZE = int(item[1])

        print("[+] Filename and filesize received from the client.")
        conn.send("Filename and filesize received".encode(FORMAT))		##
        msg = client.recv(SIZE).decode(FORMAT)
            
        print(f"Server{x}: {msg}")
    
        """ Data transfer. """
        f=open(dir_recollected_share,"rb")
        data_client=f.read()
        client.send(data_client)
        data_server = conn.recv(SIZE)
        f1=open(f"recollected_share_user{x}.txt","wb")
        f1.write(data_server)
            
        """ Closing the connection """
        client.close()

        """ Closing connection. """
        conn.close()
        
        # Delete the decrypted shares from User's directory
        #os.remove()            
        '''except:
            print("Private key not correct for decrypting the share...Quitting")
            exit(0)'''    

def decrypt_final_recollected_shares(t):
    for x in range(1,t+1):
        # Verify signature of recollected share
        f=open(f"recollected_share_user{x}.txt","rb")
        f.seek(-512, 2)
        recv_signed_data=f.read()
        f.seek(0)
        recv_ciphertext=f.read(512)
        
        dir_crt= f"{pwd}/User{x}/User{x}-cert.pem"
        user_cert_file = open(dir_crt, "rb")
        user_mid_cert = user_cert_file.read()
        user_cert = x509.load_pem_x509_certificate(user_mid_cert)
        user_public_key = user_cert.public_key()
        sign_verif=rsa_verify_pss_sha256(user_public_key,recv_ciphertext,recv_signed_data)
        if(sign_verif==False):
            print(f"Signature verification of recollected share failed for user{x}")
        else:
            print(f"Signature on the recollected share verified for user{x}")
        f.close()
        
        # After signature is verified, finally decrypt the shares for recomputation of secret
        with open("CA-key.pem","rb") as in_key:
            pem_data=in_key.read()
            CA_private_key = serialization.load_pem_private_key(pem_data, password=b"passphrase")
        
        final_dec_share = CA_private_key.decrypt(
            recv_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )    
        
        # Store the shares temporarily on the server for recomputation of secret
        with open(f"final_dec_share_user{x}.txt","wb") as fo:
            fo.write(final_dec_share)
        print(f"Decrypted the share for user {x} successfully")
        #time.sleep(2)
        
        
        


def encrypt_with_key(key):
    nonce = get_random_bytes(16)
    with open("clear.txt", "rb") as fi, open("encrypted_clear.txt", "wb") as fo:
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        ct, tag = cipher.encrypt(fi.read()), cipher.digest()
        #print(nonce, tag)
        fo.write(nonce + tag + ct)
        print("Source file is now secure and cannot be opened without Threshold no of users")
        #time.sleep(2)


def reconstruct_secret(t):
    print("\nUsing T(Threshold) no of shares to reconstruct the secret")
    #time.sleep(2)
    collected_shares=[]
    for x in range(1,t+1):
        with open(f"final_dec_share_user{x}.txt","rb") as open_file:
            collected_shares.append(open_file.read())
            print(base64.b64encode(collected_shares[x-1]))
            
    #reconstructed_secret = tss.reconstruct_secret(shares[0:t])
    reconstructed_secret = tss.reconstruct_secret(collected_shares)
    print("\nSECRET is :",reconstructed_secret)
    print("So finally we have reproduced the secret after using Threshold shares")
    #time.sleep(2)
    return (reconstructed_secret)
    # reconstructed_secret_val=reconstructed_secret.decode()
    # print ("Reconstructed:\t",reconstructed_secret.decode())


# derive
def key_from_reconstructed_secret(reconstructed_secret):
    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=390000,

    )

    reconstructed_key = kdf.derive(reconstructed_secret)

    # verify

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=390000,

    )

    kdf.verify(reconstructed_secret, reconstructed_key)
    print("Reconstructing Key......................")
    #time.sleep(2)
    return reconstructed_key


def decrypt_with_reconstructed_key(reconstructed_key):
    with open("encrypted_clear.txt", "rb") as fi:
        nonce, tag = [fi.read(16) for x in range(2)]
        cipher = AES.new(reconstructed_key, AES.MODE_EAX, nonce)
        try:
            result = cipher.decrypt(fi.read())
            cipher.verify(tag)
            #print("I am here")
            with open("final_decrypted_clear.txt", "wb") as fo:
                fo.write(result)
                print("\nNow in the last step we have finally decrypted our source file from the key generated after reconstructing the secret from the shares\n")
                #time.sleep(2) 
        except ValueError:
            print(ValueError)
            print("The shares were incorrect")

def resharing_secret(s,t):
    print("Step 1: Recollect initial shares to recompute secret")
    recollect_shares(t)
    decrypt_final_recollected_shares(t)
    reconstructed_secret_bytes=reconstruct_secret(t)
    reconstructed_secret_str=reconstructed_secret_bytes.decode('utf-8')
    print("Step 2: Create new shares for the initial secret")
    new_shares = create_shares(t, s, reconstructed_secret_str)
    print("Step 3: Redistribute new shares to users")
    distribute_shares(s,new_shares)
    

def main():
    # secret=get_random_bytes(16)
    secret = "Sample Demo Example"
    t = 3
    s = 5
    if (len(sys.argv) > 1):
        secret = str(sys.argv[1])
    if (len(sys.argv) > 2):
        t = int(sys.argv[2])
    if (len(sys.argv) > 3):
        s = int(sys.argv[3])
        
        
    print('''\n           ---------------------------------------------------------------------
               |   SHARE-SECRET: SIMPLE SECRET SHARING USING PYTHON       |
           ---------------------------------------------------------------------''')
    print('\n1) Split a secret into codes/shares.')
    print('2) Combine codes to recover secret.')
    print('3) Execute resharing of secret shares to users.')
    cmd = input('\nEnter command:')
    if cmd == '1':
        print("############# Welcome to our Secret sharing scheme for multiple users ##############")
        print(f" You have provided the following parameters for this multi party system:\nNo of Users:{s}\nThreshold:{t}\nSecret:{secret}\n")
        print(f" In our setup we will depict one CA and other {s} users : Generation of keypairs and certificates for all users might take some time. Please be patient...........\n")
        #time.sleep(2)
        CA_key_cert_gen()
        RSA_users_key_cert_gen(s,t)
        key=key_from_secret(secret)	#
        
        encrypt_with_key(key)  		# 

        # Delete the plaintext file and only keep the non breakable ciphertext for it.
        #os.remove("clear.txt")
        
        shares = create_shares(t, s, secret)
    
    
        distribute_shares(s,shares)
        main()
    elif cmd == '2':
        recollect_shares(t)
        # Now after this procedure reconstruct the secret and derive the required file.
        decrypt_final_recollected_shares(t)
        reconstructed_secret=reconstruct_secret(t)
        reconstructed_key=key_from_reconstructed_secret(reconstructed_secret)	#
        decrypt_with_reconstructed_key(reconstructed_key)
        main()
    elif cmd == '3':
        print("\n############################### Resharing of shares starting ##############################")
        resharing_secret(s,t)
    elif cmd.lower() == 'c' or cmd.lower() == 'close':
       sys.exit()
    else:
       print('please enter 1 or 2 or 3 or \'c to exit!')
       main()
    sys.exit()
    
    
    
    '''print("############# Welcome to our Secret sharing scheme for multiple users ##############")
    print(f" You have provided the following parameters for this multi party system:\nNo of Users:{s}\nThreshold:{t}\nSecret:{secret}\n")
    print(f" In our setup we will depict one CA and other {s} users : Generation of keypairs and certificates for all users might take some time. Please be patient...........\n")'''
    
    
    '''#time.sleep(2)
    CA_key_cert_gen()
    RSA_users_key_cert_gen(s,t)
    key=key_from_secret(secret)	#
    encrypt_with_key(key)  		# 

    # Delete the plaintext file and only keep the non breakable ciphertext for it.
    #os.remove("clear.txt")
        
    shares = create_shares(t, s, secret)
    
    #start_server()
    # Creating a TCP server socket
    
    server.setblocking(False)
    server.bind(ADDR)
    server.listen()
    print("[+] Listening...")
    
    
    distribute_shares(s,shares)
    
    recollect_shares(t)
    # Now after this procedure reconstruct the secret and derive the required file.
    reconstructed_secret=reconstruct_secret(t)
    reconstructed_key=key_from_reconstructed_secret(reconstructed_secret)	#
    decrypt_with_reconstructed_key(reconstructed_key)
    
    print("\n############################### Resharing of shares starting ##############################")
    resharing_secret(s,t)
    
    #Now write the decrypted share to a new file after decrypting with private key
        with open(dir_dec_share,"wb") as fo:
            fo.write(plaintext)
            print(f"Decrypted the share for user {x} successfully")
            #time.sleep(2)'''



if __name__ == "__main__":
    main()
