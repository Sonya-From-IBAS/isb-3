import argparse
import json
import logging

from scripts.asymmetric import Asymmetric
from scripts.symmetric import Symmetric
from scripts.text import Text

def menu()->None:
    """
    Func that operates with cmd user's commands 
    and execute keys ganeration, text encryption and decryption
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required = True)
    parser.add_argument("len", type = int, help="Длина ключа для симметричного шифрования")
    group.add_argument("-gen", "--generation",  help="Запускает режим генерации ключей")
    group.add_argument("-enc", "--encryption",  help="Запускает режим шифрования")
    group.add_argument("-dec", "--decryption",  help="Запускает режим дешифрования")
    args = parser.parse_args()
    with open("./files/settings.json", "r") as file:
        settings = json.load(file)
    if args.generation is not None:
        symmetric = Symmetric()
        asymmetric = Asymmetric()
        if  args.len is not None:
            symmetric.generateSymmericKey(args.len)
        else:
            symmetric.generateSymmericKey()
        asymmetric.keysGeneration()
        symmetric.setKey(asymmetric.encrypt(symmetric.getKey())) 
        asymmetric.keysSerialization(settings["secretKey"], settings["publicKey"])
        symmetric.keySerialization(settings["symmetricKey"])
        logging.info("Generation is done")
    elif args.encryption is not None:
        text = Text()
        symmetric = Symmetric()
        asymmetric = Asymmetric()
        asymmetric.secretKeyDeserialization(settings["secretKey"])
        symmetric.keyDeserialization(settings["symmetricKey"])
        symmetric.setLen(args.len)
        symmetric.setKey(asymmetric.decrypt(symmetric.getKey()))
        text.textDeserialization(settings["initialFile"])
        text.setText(symmetric.encrypt(text.getText()))
        text.textSerialization(settings["encryptedFile"])
        logging.info("Encryption is done")
    elif args.decryption:
        text = Text()
        symmetric = Symmetric()
        asymmetric = Asymmetric()
        asymmetric.secretKeyDeserialization(settings["secretKey"])
        symmetric.keyDeserialization(settings["symmetricKey"])
        symmetric.setKey(asymmetric.decrypt(symmetric.getKey()))
        text.textDeserialization(settings["encryptedFile"])
        symmetric.setLen(args.len)
        text.setText(symmetric.decrypt(text.getText()))
        text.textSerialization(settings["decryptedFile"])
        logging.info("Decryption is done")