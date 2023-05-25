import argparse
import json
import logging
import sys

from scripts.asymmetric import Asymmetric
from scripts.symmetric import Symmetric
from scripts.text import Text

logging.getLogger().setLevel(logging.INFO)

def load_settings(json_file_name:str)->dict:
    """
    Func that loads settings from json file

    Args:
        json_file_name (str): json file name

    Returns:
        dict: dict of settings
    """
    try:
        with open(json_file_name, "r") as file:
            settings = json.load(file)
        return settings
    except OSError as error:
        logging.warning("Settings are not loaded from json")
        sys.exit(error)

def save_settings(json_file_name:str, settings:dict)->None:
    """
    Func that save settings from json file

    Args:
        json_file_name (str): json file name
        settings (dict) : new settings

    """
    try:
        with open(json_file_name, "w") as file:
            json.dump(settings, file)
    except OSError as error:
        logging.warning("Settings are not saved to json")
        sys.exit(error)

def generation_action(symmetric:Symmetric, asymmetric:Asymmetric, settings:dict, key_len:int)->None:
    """
    Func that executes keys generation
    Args:
        symmetric (Symmetric): symmetric obj
        asymmetric (Asymmetric): asymmetric obj
        settings (dict): json settings
        key_len (int): lenght of key
    """
    
    symmetric.generate_symmeric_key(settings, key_len)
    asymmetric.keys_generation()
    symmetric.sym = asymmetric.encrypt(symmetric.sym)
    asymmetric.key_serialization(settings["secretKey"], settings["publicKey"])
    symmetric.key_serialization(settings["symmetricKey"])
    logging.info("Generation is done")

def encryption_action(text:Text, symmetric:Symmetric, asymmetric:Asymmetric,settings:dict)->dict:
    """
    Func that executes keys generation
    Args:
        text (Text): Text obj
        symmetric (Symmetric): Symmetric obj
        asymmetric (Asymmetric): Asymmetric obj
        settings (dict): json settings

    """
    asymmetric.secret_key_deserialization(settings["secretKey"])
    symmetric.key_deserialization(settings["symmetricKey"])
    symmetric.sym = asymmetric.decrypt(symmetric.sym)
    text.text_deserialization(settings["initialFile"])
    text.txt, settings = symmetric.encrypt(text.txt, settings)
    text.text_serialization(settings["encryptedFile"])
    logging.info("Encryption is done")
    return settings

def decryption_action(text:Text, symmetric:Symmetric, asymmetric:Asymmetric,settings:dict)->None:
    """
    Func that executes keys generation
    Args:
        text (Text): Text obj
        symmetric (Symmetric): Symmetric obj
        asymmetric (Asymmetric): Asymmetric obj
        settings (dict): json settings
    """
    print(f"settings: {settings}")
    asymmetric.secret_key_deserialization(settings["secretKey"])
    symmetric.key_deserialization(settings["symmetricKey"])
    symmetric.sym = asymmetric.decrypt(symmetric.sym)
    text.text_deserialization(settings["encryptedFile"])
    text.txt = symmetric.decrypt(text.txt, settings)
    text.text_serialization(settings["decryptedFile"])
    logging.info("Decryption is done")


def menu()->None:
    """
    Func that operates with cmd user's commands 
    and execute keys ganeration, text encryption and decryption
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required = True)
    parser.add_argument("len", type = int, help="Длина ключа для симметричного шифрования")
    parser.add_argument("path", type = str, help="Путь к json файлу с настройками")
    group.add_argument("-gen", "--generation",  help="Запускает режим генерации ключей")
    group.add_argument("-enc", "--encryption",  help="Запускает режим шифрования")
    group.add_argument("-dec", "--decryption",  help="Запускает режим дешифрования")
    args = parser.parse_args()
    settings = load_settings(args.path)

    if args.generation is not None:
        symmetric = Symmetric()
        asymmetric = Asymmetric()
        generation_action(symmetric, asymmetric, settings, args.len)
        settings["keyLen"] = int(args.len)
        save_settings(args.path, settings)

    elif args.encryption is not None:
        text = Text()
        symmetric = Symmetric()
        asymmetric = Asymmetric()
        settings = encryption_action(text, symmetric, asymmetric, settings)
    elif args.decryption:
        text = Text()
        symmetric = Symmetric()
        asymmetric = Asymmetric() 
        decryption_action(text, symmetric, asymmetric, settings)