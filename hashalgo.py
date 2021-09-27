
# File made by Ansh Gupta 2018317

import hashlib


def digest(message):
  '''Function to calculate the digest formed by md5 hash algorithm'''
  m=hashlib.md5(str(message).encode())
  return m.hexdigest()
