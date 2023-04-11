import base64

# Symmetric
from cryptography.fernet import Fernet

# Asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

""" Fernet (symmetric encryption) See: https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet
Fernet is built on top of a number of standard cryptographic primitives. Specifically it uses:
AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
HMAC using SHA256 for authentication.
Initialization vectors are generated using os.urandom().
"""

# Key is of type bytes. Key is used for the symmetric encryption.
key = Fernet.generate_key()
cipher_suite = Fernet(key)


def encrypt_file(source_plaintext_filename, target_ciphertext_filename):
    """
        Encrypts the file "source_plaintext_filename" and saves the cipher text to
        the file "target_ciphertext_filename" in the current directory.
    """
    with open(source_plaintext_filename, "rb") as file:
        plain_text = file.read()
    cipher_text = cipher_suite.encrypt(plain_text)
    with open(target_ciphertext_filename, "wb") as file:
        file.write(cipher_text)


def decrypt_file(target_ciphertext_filename, source_plaintext_filename):
    """
        Decrypts the file "target_ciphertext_filename" and saves the plain text to
        the file "Cloned-" + "target_ciphertext_filename" in the current directory.
    """
    with open(target_ciphertext_filename, "rb") as file:
        cipher_text = file.read()
    plain_text = cipher_suite.decrypt(cipher_text)
    with open('Cloned-' + source_plaintext_filename, "wb") as file:
        file.write(plain_text)


def save_rsa_keys(private_key, public_key, private_key_filename, public_key_filename):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_pem.splitlines()[0]
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem.splitlines()[0]
    with open(private_key_filename, 'wb') as private_f:
        private_f.write(private_pem)
    with open(public_key_filename, 'wb') as public_f:
        public_f.write(public_pem)


def load_rsa_keys(private_key_filename, public_key_filename):
    with open(private_key_filename, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
        )
    with open(public_key_filename, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )
    return private_key, public_key


def generate_rsa_key_pair():
    # Generate an RSA key pair
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def main():
    # RSA key pair filenames
    private_key_filename = "rsa_private_key.pem"
    public_key_filename = "rsa_public_key.pem"

    # Source and Target files in the current directory.
    source_plaintext_filename = "bigFile.pdf"
    target_ciphertext_filename = source_plaintext_filename + '.bin'

    # Now you can encrypt and decrypt a file like this:
    encrypt_file(source_plaintext_filename, target_ciphertext_filename)
    decrypt_file(target_ciphertext_filename, source_plaintext_filename)

    # Uncomment the next two line to generate and save to disk an RSA key pair
    private_key, public_key = generate_rsa_key_pair()
    save_rsa_keys(private_key, public_key, private_key_filename, public_key_filename)

    # Load the RSA key pair from disk
    private_key, public_key = load_rsa_keys(private_key_filename, public_key_filename)

    # Signing (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing)
    # A private key can be used to sign a message.This allows anyone with the public key to verify that the message
    # was created by someone who possesses the corresponding private key.RSA signatures require a specific hash
    # function, and padding to be used.Here is an example of signing message using RSA, with a secure hash
    # function and padding:

    message = b"A message I want to sign"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Valid paddings for signatures are PSS and PKCS1v15. PSS is the recommended choice for any new protocols or
    # applications, PKCS1v15 should only be used to support legacy protocols.

    # Verification (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification)
    # The previous section describes what to do if you have a private key and want to sign something.
    # If you have a public key, a message, a signature, and the signing algorithm that was used you can
    # check that the private key associated with a given public key was used to sign that specific message.
    public_key.verify(
         signature,
         message,
         padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
    )
    # If the signature does not match, verify() will raise an InvalidSignature exception.

    # RSA Encryption (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption)
    # RSA encryption is interesting because encryption is performed using the public key, meaning anyone
    # can encrypt data. The data is then decrypted using the private key.
    #
    # Like signatures, RSA supports encryption with several different padding options.
    # Here’s an example using a secure padding and hash function:
    message = b"encrypted data"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Valid paddings for encryption are OAEP and PKCS1v15. OAEP is the recommended choice for any new protocols or
    # applications, PKCS1v15 should only be used to support legacy protocols.

    # RSA Decryption (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption)
    # Once you have an encrypted message, it can be decrypted using the private key:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(plaintext == message)


if __name__ == '__main__':
    main()
"""
# In what order is encryption and signing done to send a file and keep integrity and confidentiality?
When sending a file to maintain both integrity and confidentiality, the general order of operations is:

1. The file is first encrypted to ensure confidentiality. This is typically done using symmetric-key encryption,
where the same key is used for encryption and decryption.
2. The encrypted file is then signed to ensure integrity. This is typically done using a digital signature,
which is a method of verifying the authenticity of a file using a private key.
3. The signed and encrypted file is then sent to the recipient.
4. Upon receipt, the recipient uses the sender's public key to verify the digital signature and ensure the
integrity of the file.
5. The recipient then uses the same symmetric key used for encryption to decrypt the file and access the original
content.


# How do you send the symmetric key with the encrypted file?
There are several methods for sending the symmetric key with the encrypted file, some of the most common include:

A. Public-key Encryption: The sender generates a random symmetric key, encrypts the file with it, and then encrypts 
the symmetric key using the recipient's public key. The recipient can then use their private key to decrypt the 
symmetric key and then use it to decrypt the file.

B. Key-Wrapping: The sender encrypts the symmetric key with a key-encryption key (KEK) and sends the encrypted key 
along with the encrypted file. The recipient uses their own copy of the KEK to decrypt the symmetric key and then uses
it to decrypt the file.

C. Key-Agreement Protocols: The sender and recipient can use a key-agreement protocol such as Diffie-Hellman to 
establish a shared secret key, which can be used as the symmetric key to encrypt the file.

D. Out-of-band method: The symmetric key is sent separately from the encrypted file, for example, by phone or other
secure means of communication.

It's important to note that whichever method is used, the key must be securely exchanged between the sender and 
recipient, otherwise, the confidentiality and integrity of the file can be compromised.

# Source: 5.4. Working with big files
# https://stuvel.eu/python-rsa-doc/usage.html#encryption-and-decryption

# RSA cannot encrypt a file larger than the key (minus some random padding) A 512 bit (64 bytes) RSA key can be used 
to encrypt a 63 byte file. The most common way to use RSA with larger files uses a block cypher like AES or DES3 to 
encrypt the file with a random key, then encrypt the random key with RSA.You would send the encrypted file along 
with the encrypted key to the recipient.The complete flow is:

1. Create a 256 bit AES key
2. Encrypt the large file using the AES key (symmetric encryption)
3. Encrypt the AES key using RSA with the recipient's public key (asymmetric encryption)
4. Sign the large file using RSA with the sender's private key
5. Send (or save) the signature, encrypted AES key, and ciphertext
5. Recipient decrypts the encrypted AES key with the recipient's private key.
6. Recipient decrypts the large file with the obtained plaintext AES key.
7. Recipients verifies the signature with the plaintext large file and the sender's public key.
"""