import sys
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


logging.getLogger().setLevel(logging.INFO)


class Asymmetric:
    """
    Class for working with asymmetric alg
    """

    def __init__(self) -> None:
        """
        Constructor
        """
        self.__secret_key = None
        self.__public_key = None

    def keys_generation(self) -> None:
        """
        Func that geneates keys
        """
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.__secret_key = keys
        self.__public_key = keys.public_key()
        logging.info("Asymmetric keys was generated")

    def secret_key_deserialization(self, file_name: str) -> None:
        """
        Func that loads secret key from file

        Args:
            file_name (str): name of .pem file
        """
        try:
            with open(file_name, "rb") as file:
                private_bytes = file.read()
            self.__secret_key = load_pem_private_key(
                private_bytes, password=None)
            logging.info("Secret key is loaded")
        except OSError as error:
            logging.warning("Secret key is not loaded")
            sys.exit(error)
    
    def public_key_deserialization(self, file_name: str) -> None:
        """
        Func that loads public key from file
        Args:
            file_name (str): name of .pem file
        """
        try:
            with open(file_name, "rb") as file:
                public_bytes = file.read()
                self.__public_key = load_pem_public_key(
                public_bytes, password=None)
            logging.info("Public key is loaded")
        except OSError as error:
            logging.warning("Public key is not loaded")
            sys.exit(error)

    def key_serialization(self, secret_key_file_name: str, public_key_file_name: str) -> None:
        """
        Funs that write public and secret keys to files

        Args:
            secret_key_file_name (str): name of .pem file for secret key
            public_key_file_name (str): name of .pem file for public key
        """
        try:
            with open(secret_key_file_name, "wb") as file:
                file.write(
                    self.__secret_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.NoEncryption()))
                logging.info("Secret key is saved")
        except OSError as error:
            logging.warning("Secret key is not saved")
            sys.exit(error)
        try:
            with open(public_key_file_name, "wb") as file:
                file.write(
                    self.__public_key.public_bytes(encoding=serialization.Encoding.PEM, 
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))
                logging.info("Public key is saved")
        except OSError as error:
            logging.warning("Public key is not saved")
            sys.exit(error)

    def encrypt(self, symmetric_key: bytes) -> bytes:
        """
        Func that encrypt symmetric key with public key of asymmetric algorithm 

        Args:
            symmetric_key (bytes): key of symmetric algorithm

        Returns:
            bytes: encrypted key of symmtric algorithm
        """
        encrypted_symmetric_key = self.__public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        logging.info("Symmetric key is encrypted")
        return encrypted_symmetric_key

    def decrypt(self, symmetric_key: bytes) -> bytes:
        """
        Func that decrypt symmetric key with secret key of asymmetric algorithm

        Args:
            symmetric_key (bytes): encrypted key with asymmetric algorithm of symmetric algorithm 

        Returns:
            bytes: decrypted key of symmetric algorithm
        """
        decrypted_symmetric_key = self.__secret_key.decrypt(symmetric_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        logging.info("Symmetric key if decrypted")
        return decrypted_symmetric_key
