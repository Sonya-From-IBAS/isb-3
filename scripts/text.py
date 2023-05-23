import logging
import sys

logging.getLogger().setLevel(logging.INFO)

class Text:
    """
    Class for workings text with bytes
    """
    def __init__(self)->None:
        """
        Constructor
        """
        self.__text = None
    
    def getText(self)->bytes:
        """
        Getter

        Returns:
            bytes: text in bytes
        """
        return self.__text
    
    def setText(self, text:bytes)->None:
        """
            setter
        Args:
            text (bytes): new text value
        """
        self.__text = text

    def textSerialization(self, fileName:str)->None:
        """
        Funs that writes text in file

        Args:
            text (str): name of file
        """
        try:
            with open(fileName, "wb") as file:
                file.write(self.__text)
            logging.info("Text is saved")
        except OSError as error:
            logging.warning("Text is not saved")
            sys.exit(error)

    def textDeserialization(self, fileName:str)->None:
        """
        Func that reads text from file

        Args:
            fileName (str): name of file
        """
        try:
            with open(fileName, "rb") as file:
                self.__text = file.read()
            logging.info("Text is loaded from file")
        except OSError as error:
            logging.warning("Text is not loaded from file")
            sys.exit(error)