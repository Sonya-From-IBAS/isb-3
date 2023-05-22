import argparse
import json
import logging

def menu()->None:
    """

    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument("-gen", "--generation", help="Запускает режим генерации ключей")
    group.add_argument("-enc", "--encryption", help="Запускает режим шифрования")
    group.add_argument("-dec", "--decryption", help="Запускает режим дешифрования")
    args = parser.parse_args()
    if args.generation is not None:
        print("generation")
    elif args.encryption is not None:
        print("encryption")
    else:
        print("decryption")