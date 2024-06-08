class AlcatelSwLang:
    _l_sysinfo = {"FR" : "informations système", "EN" : "system informations"}
    _l_name =  {"FR" : "nom", "EN" : "name"}
    _l_contact =  {"FR" : "contact", "EN" : "contact"}
    _l_location =  {"FR" : "localisation", "EN" : "location"}
    _l_adminpassword =  {"FR" : "mot de passe administrateur", "EN" : "administrator password"}
    _l_users =  {"FR" : "utilisateurs", "EN": "users"}
    _l_password =  {"FR" : "mot de passe", "EN" : "password"}
    _l_allow_write = {"FR" : "droit de modification", "EN" : "allow write"}
    _l_admin_ip_address = {"FR" : "adresses IP d'administration", "EN" : "administrative IP address"}
    _l_address = {"FR" : "adresse", "EN" : "address"}
    _l_mask = {"FR" : "masque", "EN" : "mask"}
    _l_vlan = {"FR" : "vlan", "EN" : "vlan"}
    _l_interface_index = {"FR" : "indice de l'interface", "EN" : "interface index"}
    _l_ip = {"FR" : "ip", "EN" : "ip"}
    _l_cidr = {"FR" : "cidr", "EN" : "cidr"}
    _l_gateway = {"FR" : "passerelle", "EN" : "gateway"}
    _l_metric = {"FR" : "métrique", "EN" : "metric"}
    _l_id = {"FR" : "identifiant", "EN" : "identifier"}
    _l_number_ports = {"FR" : "nombre de ports", "EN" : "number ports"}
    _l_key = {"FR" : "clé", "EN" : "key"}
    _l_enable = {"FR" : "activé", "EN" : "enabled"}
    _l_member_ports = {"FR" : "ports membres", "EN" : "member ports"}
    _l_port = {"FR" : "port", "EN" : "port"}
    
    def __init__(self, lang):
        self._lang = lang
        for key, value in AlcatelSwLang.__dict__.items():
            if key[0:3] == "_l_":
                setattr(self, key[3:], AlcatelSwLang.__dict__[key][self._lang])