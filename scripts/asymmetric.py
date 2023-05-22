import sys
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


logging.getLogger().setLevel(logging.INFO)


class Asymmetric:
    """
    Class for working with asymmetric encryption alg
    """

    def __init__(self) -> None:
        """
        Constructor
        """
        self.__secretKey = None
        self.__publicKey = None

    def keysGeneration(self) -> None:
        """
        Func that geneates keys
        """
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.__secretKey = keys
        self.__publicKey = keys.public_key()
        logging.info("Asymmetric keys was generated")

    def privateKeyDeserialization(self, fileName: str) -> None:
        """
        Func that loads secret key from file

        Args:
            fileName (str): name of .pem file
        """
        try:
            with open(fileName, "rb") as file:
                private_bytes = file.read()
            self.__secretKey = load_pem_private_key(
                private_bytes, password=None)
            logging.info("Secret key is loaded")
        except OSError as error:
            logging.warning("Secret key is not loaded")
            sys.exit(error)

    def keysSerialization(self, secretKeyFileName: str, publicKeyFileName: str) -> None:
        """
        Funs that write public and secret keys to files

        Args:
            secretKeyFileName (str): name of .pem file for secret key
            publicKeyFileName (str): name of .pem file for public key
        """
        try:
            with open(secretKeyFileName, "wb") as file:
                file.write(
                    self.__secretKey.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.NoEncryption()))
                logging.info("Secret key is saved")
        except OSError as error:
            logging.warning("Secret key is not saved")
            sys.exit(error)
        try:
            with open(publicKeyFileName, "wb") as file:
                file.write(
                    self.__publicKey.public_bytes(encoding=serialization.Encoding.PEM, 
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))
                logging.info("Public key is saved")
        except OSError as error:
            logging.warning("Public key is not saved")
            sys.exit(error)

    def encrypt(self, symmetricKey: bytes) -> bytes:
        """
        Func that encrypt symmetric key with public key of asymmetric algorithm 

        Args:
            symmetricKey (bytes): key of symmetric algorithm

        Returns:
            bytes: encrypted key of symmtric algorithm
        """
        encryptedSymmetricKey = self.__publicKey.encrypt(symmetricKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        logging.info("Symmetric key is encrypted")
        return encryptedSymmetricKey

    def decrypt(self, symmetricKey: bytes) -> bytes:
        """
        Func that decrypt symmetric key with secret key of asymmetric algorithm

        Args:
            symmetricKey (bytes): encrypted key with asymmetric algorithm of symmetric algorithm 

        Returns:
            bytes: decrypted key of symmetric algorithm
        """
        decryptedSymmetricKey = self.__secretKey.decrypt(symmetricKey,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        logging.info("Symmetric key if decrypted")
        return decryptedSymmetricKey
