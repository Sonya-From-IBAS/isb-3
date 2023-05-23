import logging
import sys
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

logging.getLogger().setLevel(logging.INFO)
class Symmetric:
    """
    Class for working with symmetric alg
    """
    def __init__(self)->None:
        self.__key = None
        self.__len = None
    
    def generateSymmericKey(self, keyLenght: int = 128)->None:
        """
        Func that generates key of symmetric algorithm
        Args:
            keyLenght (int, optional): lenght of key(bits). Defaults to 128.
        """
        if(keyLenght in [64,128,192]):
            self.__len = int(keyLenght/8)
            self.__key = os.urandom(self.__len)
            logging.info(f"Symmeric key is generated, lenght is {keyLenght}")
        else:
            logging.warning("Symmeric key is not generated. keyLenght is not correct")
            sys.exit("Try again")

    def getKey(self)->bytes:
        """
            Getter
        Returns:
            bytes: returns key value
        """
        return self.__key
    
    def setKey(self, key: bytes)->None:
        """
            Setter
        Args:
            key (bytes): set key value
        """
        self.__key = key
        
    def setLen(self, len: int)->None:
        """
            Setter
        Args:
            len (int): set len value
        """
        self.__len = int(len/8)

    def keyDeserialization(self, fileName: str)->None:
        """
            Func that loads key from file
        Args:
            fileName (str): name of .txt file
        """
        try:
            with open(fileName, "rb") as file:
                self.__key = file.read()
            logging.info("Symmeric key is loaded")
        except OSError as error:
            logging.warning("Symmeric key is not loaded")
            sys.exit(error)

    def keySerialization(self, fileName:str)->None:
        """
            Func that saves key to file
        Args:
            fileName (str): name of .txt file
        """
        try:
            with open(fileName, "wb") as file:
                file.write(self.__key)
            logging.info("Symmeric key is saved")
        except OSError as error:
            logging.warning("Symmeric key is not saved")
            sys.exit(error)

    def encrypt(self, text: bytes)->bytes:
        """
            Funs that encrypts text
        Args:
            text (str): text

        Returns:
            bytes: encrypted text in bytes
        """
        padder = padding.ANSIX923(self.__len*8).padder()
        padded_text = padder.update(text)+padder.finalize()
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(self.__key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_text) + encryptor.finalize()
        with open ("./files/iv.txt", "wb") as file:
            file.write(iv)
        logging.info("Text is encrypted with symmetric algorithm")
        return c_text

    def decrypt(self, text:bytes)->bytes:
        """
            Func that decrypt text
        Args:
            text (bytes): encrypted text in bytes

        Returns:
            bytes: decrypted text in bytes
        """
        with open("./files/iv.txt", 'rb') as file:
            iv = file.read()
        cipher = Cipher(algorithms.TripleDES(self.__key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(text) + decryptor.finalize()
        unpadder = padding.ANSIX923(self.__len*8).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        logging.info("Text is decrypted with symmetric algorithm")
        return unpadded_dc_text