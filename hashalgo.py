
# File made by Ansh Gupta 2018317

import hashlib

# returing the digest formed using md5 hash algorithm
def digest(message):
  m=hashlib.md5(str(message).encode())
  return m.hexdigest()