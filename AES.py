# pip install cipher21
# pip install secrets

from Crypto.Cipher import AES
from secrets import token_bytes

key=token_bytes(16)

def encypt(msg):
    cipher=AES.new(key, AES.MODE_EAX)
    nonce=cipher.nonce
    cipherText, tag=cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, cipherText, tag

def decrypt(nonce, cipherText, tag):
    cipher=AES.new(key, AES.MODE_EAX, nonce=nonce)
    plainText=cipher.decrypt(cipherText)
    try:
        cipher.verify(tag)
        return plainText.decode('ascii')
    except:
        return False

nonce, cipherText, tag=encypt(input('Enter a message: '))
plainText=decrypt(nonce, cipherText, tag)
print(f"Cipher text: {cipherText}")
if not plainText:
    print("Message is corrupted")
else:
    print(f"Plain Text : {plainText}")