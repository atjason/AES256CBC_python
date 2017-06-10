import os, random, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AES256CBC:
  _block_size = 16
  _backend = default_backend()

  @staticmethod
  def encrypt(txt, password):
    '''
    Return encrypted string via AES-256CBC or None if failed.
    Automatically generates and puts a random IV at first 16 chars.
    The password must be exactly 32 chars long for AES-256.
    '''
    iv = AES256CBC._random_text(AES256CBC._block_size)
    
    cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=AES256CBC._backend)
    encryptor = cipher.encryptor()

    formated_txt = AES256CBC._add_padding(txt)
    encrypted = encryptor.update(formated_txt) + encryptor.finalize()
    return iv + base64.b64encode(encrypted)

  @staticmethod
  def decrypt(txt, password):
    '''
    Return decrypted string via AES-256CBC or None if failed.
    IV need to be at first 16 chars, password must be 32 chars long.
    '''
    try:
      iv = txt[:AES256CBC._block_size]
      encoded = txt[AES256CBC._block_size:]
      encrypted = base64.b64decode(encoded)
      
      cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=AES256CBC._backend)
      decryptor = cipher.decryptor()
      
      decrypted = decryptor.update(encrypted) + decryptor.finalize()
      return AES256CBC._remove_padding(decrypted)

    except:
      return None

  @staticmethod
  def _random_text(length):
    try:
      base_txt = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
      txt = ""
      for i in range(length):
        txt += random.choice(base_txt)      
      return txt

    except:
      return None
  
  @staticmethod
  def generate_password():
    '''
    The password must be exactly 32 chars long for AES-256.
    '''
    return AES256CBC._random_text(32)

  @staticmethod
  def _add_padding(txt):
    try:
      count = AES256CBC._block_size - (len(txt) % AES256CBC._block_size)
      return txt + ('\0' * count)

    except:
      return txt
  
  @staticmethod
  def _remove_padding(txt):
    try:
      return txt.strip('\0\x06')

    except:
      return txt

if __name__ == "__main__":
    password = AES256CBC.generate_password()
    assert len(password) == 32
    
    txt = "Hello World."
    encrypted = AES256CBC.encrypt(txt, password)
    decrypted = AES256CBC.decrypt(encrypted, password)
    assert decrypted == txt
    
    txt = "1484053967"
    password = "3MnxOva5igshDTeFfl2IXXBxVRNuB7xw"
    encrypted = "QOpP2UAri5g5Y21RAGVQzh/9gCSDcjOkJjZN+Q=="
    decrypted = AES256CBC.decrypt(encrypted, password)
    assert decrypted == txt

    print "All tests passed."
