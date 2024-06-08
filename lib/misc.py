#!/usr/bin/python3

from lib.exceptions import SwitchConfigTypeError
import os

def type_is_valid(o, t, field, parent):
    if type(t) == type:
        if type(o) is not t:
            message = "Type invalide pour la valeur \"{}\" de la clé \"{}\" dans \"{}\".\n".format(o, field, parent)
            message += "\"{}\" est de type \"{}\" alors que son type devrait être de type \"{}\".".format(o, type(o), t)
            raise SwitchConfigTypeError(message)
        return True
    elif type(t) == list:
        if type(o) not in t:
            message = "Type invalide pour la valeur \"{}\" de la clé \"{}\" dans \"{}\".\n".format(o, field, parent)
            message += "\"{}\" est de type \"{}\" alors que son type devrait être l'un de ces type \"{}\".".format(o, type(o), t)
            raise SwitchConfigTypeError(message)
        return True
    else:
        return False
    
def parent_cat(p1, p2):
    return p1 + "/" + p2

class AConfig(str):
    def __iadd__(self, i):
        return AConfig("{}{}\n".format(self, i))
    
class Logger():

    _clean_end = "\x1b[0m\x1b[47m\x1b[30m"

    def __init__(self, print=False) -> None:
        self._data = "\x1b[46m\x1b[37m" + "-" * os.get_terminal_size()[0] + Logger._clean_end
        self._line = os.get_terminal_size()[0]
    
    def log(self, data):
        data = str(data)
        self._data += data + (" " * (self._line - len(data)) + Logger._clean_end + "\n")
    
    def log_error(self, data):
        data = str(data)
        self._data += "\x1b[31m" + data + (" " * (self._line - len(data)) + Logger._clean_end + "\n")
    
    def log_sf(self, data):
        data = str(data)
        self._data += data + " " * (self._line - len(data) - 10)

    def success(self):
        self._data += "\x1b[32m [SUCCESS]" + Logger._clean_end + "\n"

    def failure(self):
        self._data += "\x1b[31m [FAILURE]" + Logger._clean_end + "\n"

    def print_log(self):
        print(self._data, end="")
        print("\x1b[46m\x1b[37m" + "-" * os.get_terminal_size()[0] + Logger._clean_end + "\x1b[0m")