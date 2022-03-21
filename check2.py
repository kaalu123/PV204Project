import tss
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
import binascii
import os
import datetime
import time

# secret=get_random_bytes(16)
secret = "Sample Demo Example"
salt = b'001122334455667788'
t = 3
s = 8


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
    time.sleep(2)

    print("Generating Self Signed Certificate for CA.........................")
    time.sleep(2)
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


# Generating keypairs and certificates for al users part of our multi party system
def RSA_users_key_cert_gen():  # Usage of classess of cryptography library referenced from https://cryptography.io/en/latest/
    for x in range(1, s + 1):
        user_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        # Write our key to disk for safe keeping

        with open(f"User{x}_key.pem", "wb") as f:
            f.write(user_key.private_bytes(

                encoding=serialization.Encoding.PEM,

                format=serialization.PrivateFormat.TraditionalOpenSSL,

                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),

            ))
        print(f"Generated Keypair for User {x}.........................")
        time.sleep(2)
        # Generate a CSR for a user
        print(f"Generating Certificate Signing Request for User {x}.........................")
        time.sleep(2)
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

        with open(f"User{x}-csr.pem", "wb") as f:
            f.write(user_csr.public_bytes(serialization.Encoding.PEM))

        print("Generating Certificate for User signed by CA.........................")
        time.sleep(2)
        f1 = open(f"User{x}-csr.pem", "rb")
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

        with open(f"User{x}-cert.pem", "wb") as f:
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
    time.sleep(2)
    return key


def create_shares(t, s, secret):
    shares = tss.share_secret(t, s, secret, 'my-id', Hash.NONE)
    #print("Secret:\t", secret)
    print("===Initial Shares are as below which will be encrypted and thereafter plaintext of shares will never be available after creation\n")
    time.sleep(2)
    for x in range(0, s):
        print(base64.b64encode(shares[x]))
        
    #print(type(shares))
    return shares


def distribute_shares(s):
    CA_cert_file = open("CA-cert.pem", "rb")
    CA_mid_cert = CA_cert_file.read()
    CA_cert = x509.load_pem_x509_certificate(CA_mid_cert)
    CA_public_key = CA_cert.public_key()
    print("Starting distribution of shares to users after authenticating their certificates and sending each user his share encrypted by his public key")
    time.sleep(2)
    for x in range(2, s+1):
        # Loading User's Certificate for verification
        user_cert_file = open(f"User{x}-cert.pem", "rb")
        user_mid_cert = user_cert_file.read()
        user_cert = x509.load_pem_x509_certificate(user_mid_cert)
        user_public_key = user_cert.public_key()
        try:
            verif = CA_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm
            )
            print(f"User {x} Certificate verified")
            time.sleep(2)
            #print(f"Check{x}")
            # Now encrypt each share using the public key of specific user.
            ciphertext = user_public_key.encrypt(  # Encrypting the share with Bob's Public Key
                shares[x-1],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Now write each encrypted share in a file for giving security to the share
            with open(f"enc_share_user{x}.txt", "wb") as out:
                out.write(ciphertext)
                #print(f"Check{x}")
                
        except:
            print("Invalid Certificate")
            exit(0)		#Exit communication if parties not authenticated

def recollect_shares(t):
    # Validate sender's certificate
    print("Recollecting shares from T(Threshold) no of users for reconstructing the secret after validating their certificates")
    time.sleep(2)
    for x in range(0,t):
        user_key_file = open(f"User{x+2}_key.pem", "rb")
        key_data = user_key_file.read()
        user_private_key = serialization.load_pem_private_key(key_data, password=b"passphrase", )
        with open(f"enc_share_user{x+2}.txt","rb") as in_file:
            ciphertext=in_file.read()
            try:
            # Now decrypt each share using the private key of specific user.
                plaintext = user_private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                #Now write the decrypted share to a new file after decrypting with private key
                with open(f"dec_share_user{x+2}.txt","wb") as fo:
                    fo.write(plaintext)
                    print(f"Decrypted the share for user {x+2} successfully")
                    time.sleep(2)
                    
            except:
                print("Private key not correct for decrypting the share...Quitting")
                exit(0)    

def encrypt_with_key(key):
    nonce = get_random_bytes(16)
    with open("clear.txt", "rb") as fi, open("enc.txt", "wb") as fo:
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        ct, tag = cipher.encrypt(fi.read()), cipher.digest()
        #print(nonce, tag)
        fo.write(nonce + tag + ct)
        print("Source file is now secure and cannot be opened without Threshold no of users")
        time.sleep(2)


def reconstruct_secret():
    print("\nUsing T(Threshold) no of shares to reconstruct the secret")
    time.sleep(2)
    collected_shares=[]
    for x in range(0,t):
        with open(f"dec_share_user{x+2}.txt","rb") as open_file:
            collected_shares.append(open_file.read())
            print(base64.b64encode(collected_shares[x]))
            
    #reconstructed_secret = tss.reconstruct_secret(shares[0:t])
    reconstructed_secret = tss.reconstruct_secret(collected_shares)
    print("\nSECRET is :",reconstructed_secret)
    print("So finally we have reproduced the secret after using Threshold shares")
    time.sleep(2)
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
    time.sleep(2)
    return reconstructed_key


def decrypt_with_reconstructed_key(reconstructed_key):
    with open("enc.txt", "rb") as fi:
        nonce, tag = [fi.read(16) for x in range(2)]
        cipher = AES.new(reconstructed_key, AES.MODE_EAX, nonce)
        try:
            result = cipher.decrypt(fi.read())
            cipher.verify(tag)
            #print("I am here")
            with open("final_clear2.txt", "wb") as fo:
                fo.write(result)
                print("\nNow in the last step we have finally decrypted our source file from the key generated after reconstructing the secret from the shares\n")
                time.sleep(2) 
        except ValueError:
            print(ValueError)
            print("The shares were incorrect")


if (len(sys.argv) > 1):
    secret = str(sys.argv[1])
if (len(sys.argv) > 2):
    t = int(sys.argv[2])
if (len(sys.argv) > 3):
    s = int(sys.argv[3])
print("############# Welcome to our Secret sharing scheme for multiple users ##############")
print(f" You have provided the following parameters for this multi party system:\nNo of Users:{s}\nThreshold:{t}\nSecret:{secret}\n")
print(f" In our setup we will depict one CA and other {s} users : Generation of keypairs and certificates for all users might take some time. Please be patient...........\n")
time.sleep(2)
CA_key_cert_gen()
RSA_users_key_cert_gen() 
key=key_from_secret(secret)
encrypt_with_key(key)   

# Delete the plaintext file and only keep the non breakable ciphertext for it.
    
shares = create_shares(t, s, secret)
distribute_shares(s)
recollect_shares(t)
# Now after this procedure reconstruct the secret and derive the required file.
reconstructed_secret=reconstruct_secret()
reconstructed_key=key_from_reconstructed_secret(reconstructed_secret)
decrypt_with_reconstructed_key(reconstructed_key)

