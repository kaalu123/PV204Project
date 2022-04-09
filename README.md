# PV204Project
An implementation of a threshold secret sharing scheme with secure communication between multiple users and the ability to input the Secret along with total No of shares and threshold value.

Project Design-:
This project implements the Threshold secret sharing through a dealer which acts as a server and distributes shares created from a secret to the users which acts as a client.
 
The tool lets you to choose the no of users and threshold users in the setup and the secret to be hidden which is used to derive a key needed to encrypt a source file. ( t out of n sharing)

Implementation-:
Dealer (Server) Side-:
Creates shares from the given secret which is used to encrypt the source file to be hidden.
Encrypts the share with user’s public key and signs with his own private key.
Validates User Certificate before sending the encrypted share.
Removes all the shares from server and stores only encrypted file.

User (Client) Side-:
Decrypts the share with own public key and verifies dealer’s signature.
During recollection phase, encrypts the decrypted share with dealer’s public key and signs with own private key.
Sends this encrypted share back to Dealer after verifying server(dealer) certificate.
Dealer verifies user’s signature and decrypts share by own private key.
Recomputes the secret and derives the key used to decrypt the hidden file.

Also provides the option for resharing of the shares on selection of Option 3. Can only be executed after a secret is initially split into shares.

NOTE-:Use of Socket Programming to implement Server Client model and each user  given separate directory for storing it’s share of files.

Usage-:
$ python3 check2.py <Secret Phrase> <Threshold> <No of Users>
 
---------------------------------------------------------------------
    |   SHARE-SECRET: SIMPLE SECRET SHARING USING PYTHON       |
---------------------------------------------------------------------
1) Split a secret into codes/shares.
2) Combine codes to recover secret.
3) Execute resharing of secret shares to users.


Make sure to keep file clear.txt in PWD which has to be secured using this tool. Please import all libraries used in the project using pip installer.


