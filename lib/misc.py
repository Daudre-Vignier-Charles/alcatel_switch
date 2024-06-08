#!/usr/bin/python3

def type_is_valid(o, t, field, parent):
    if type(t) == type:
        if type(o) is not t:
            e = "Type invalide pour la valeur \"{}\" de la clé \"{}\" dans \"{}\".\n".format(o, field, parent)
            e += "\"{}\" est de type \"{}\" alors que son type devrait être de type \"{}\".".format(o, type(o), t)
            raise TypeError(e)
        return True
    elif type(t) == list:
        if type(o) not in t:
            e = "Type invalide pour la valeur \"{}\" de la clé \"{}\" dans \"{}\".\n".format(o, field, parent)
            e += "\"{}\" est de type \"{}\" alors que son type devrait être l'un de ces type \"{}\".".format(o, type(o), t)
            raise TypeError(e)
        return True
    else:
        return False

class AConfig(str):
    def __iadd__(self, i):
        return AConfig("{}{}\n".format(self, i)) 
