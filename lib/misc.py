#!/usr/bin/python3

from lib.exceptions import SwitchConfigTypeError

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