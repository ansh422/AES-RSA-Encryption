
# File made by Ansh Gupta 2018317

import socket
import json
from rsa_algo import rsa
from hashalgo import digest
from aes_decryption import aes_decrypt

def server(conn):
  '''Server Main Function'''

  #Request from client for public key

  val=conn.recv(1025).decode() 
  if val =='y':

  #Entering the private and public key parameters of server

    e_server_public,n_server_public=map(int, input('Enter the public key for server: ').split())
    d_server_private=int(input('Enter the private key for server :'))

  #Arranging the data in dictionary and sending it to client on requesting
    keys = {"e_server_public":e_server_public, "n_server_public":n_server_public}
    conn.send(json.dumps(keys).encode())

  #Receiving the data from client

  data = json.loads(conn.recv(1025).decode())
  ciphertext=data['ciphertext']
  encrypted_secret_key=data['encrypted_secret_key']
  client_signature=data['client_signature']
  e_client_public=data['e_client_public']
  n_client_public=data['n_client_public']

  # making the secret key using RSA algorithm with server private key

  secret_key=rsa(encrypted_secret_key,d_server_private,n_server_public)

  # Decrypting the Ciphertext using secret key 

  message=aes_decrypt(ciphertext,secret_key)

  #Making the hash digest

  hash_digest_server=digest(message)

  #Making the signature using digest and public credentials of client

  signature=rsa(client_signature,e_client_public,n_client_public)

  #OUTPUT

  print('<---------------OUTPUT--------------->')
  print('Public Key Parameters',e_server_public,' and ',n_server_public)
  print('Private Key Parameters',d_server_private)
  print('Decrypted Secret Key',secret_key)
  print('Decrypted Message',message)
  print('Message Digest',hash_digest_server)
  print('Intermediate Verification Code',signature)

  if signature == int(hash_digest_server,16)%n_client_public:
    print('Signature is Verified')
  else:
    print('Signature is Not Verified')

  # Closing the connection
  conn.close()


s=socket.socket()
#port
port=1025
s.bind((socket.gethostname() ,port))
#server in listening mode
s.listen(5)

conn,addr=s.accept()

server(conn)

print('----The code is made by Ansh Gupta (2018317)----')
