This has six python files representing various methods required. The main functions of these files are:

client_main.py: Representing the client
serer_main.py: Representing the server
aes_encryption.py: Has the functions to implement Simplified AES encryption.
aes_decryption.py: Has the functions to implement Simplified AES decryption.
hashalgo.py: Has the function to implement the hash algorithm.
rsa_algo.py: Has the function to implement the RSA algorithm.

Function present in client_main.py only:

* client(s): Main function for client

Function present in server_main.py only:

* server(conn): Main function for server

Functions present both in aes_decryption.py and aes_encryption.py are described as:

* mult(p1,p2): This function is used to multiply two polynomials in GF(2^4),i.e, x^4+x+1
* InttoVec(n): It converts 2-byte (8 bits integer) into a vector of 4 elements.
* VecToInt(n): It converts a 4-element vector into a 2-byte integer.
* addKey(s1,s2): used to add two keys in GF(2^4)
* NibSub(sbox,s): function used for Nibble Substitution
* shiftRow(s): ShiftRow function
* keyExp(key): To generate the three round keys
* sub2nib(b): Swap each nibble and substitute it using sbox

Functions present in aes_decryption.py only:

* mixCol(s): mix columns according to encryption method
* aes_encrypt(val,key): encrypting the plain text with 2 rounds of simplified aes.

Functions present in aes_decryption.py only:

* mixCol(s): mixing columns accordig to decryption method
* aes_decrypt(val): decrypting the cipher text received from the client.

Function present in hashalgo.py only:

* digest(message): To calculate the digest formed by md5 hash algorithm

Function present in rsa_algo.py only:

* rsa(base,exponent,mod): Calulate  based on simple function (base**exponent) % mod.

Modules required:

socket- To make two nodes on a network to communicate with each other, socket module is used. 
json- to send and receive the parameters easily between client and server.

