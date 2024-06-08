#!/usr/bin/python3

import yaml
import secrets

from lib.misc import type_is_valid, AConfig

class SysInfo():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.contact], str, lang.contact, parent):
            self.contact = yaml[lang.contact]
        if type_is_valid(yaml[lang.location], str, lang.location, parent):
            self.location = yaml[lang.location]
    
    def to_code(self):
        aconfig = AConfig("! {} \n".format(lang.sysinfo))
        aconfig += "system name \"{}\"".format(self.name)
        aconfig += "system contact \"{}\"".format(self.contact)
        aconfig += "system location \"{}\"".format(self.location)
        return aconfig

class User():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.password], [str, int], lang.password, parent):
            self.password = yaml[lang.password]
        if type_is_valid(yaml[lang.allow_write], bool, lang.allow_write, parent):
            self.allow_write = yaml[lang.allow_write]
    
    def to_code(self):
        if type(self.password) is int:
            aconfig += "user {} password {}".format(self.name, secrets.token_urlsafe(self.password))
        else:
            aconfig += "user {} password {}".format(self.name, self.password)

class AdministrativeIPAddress():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.address], str, lang.address, parent):
            self.address = yaml[lang.address]
        if type_is_valid(yaml[lang.mask], str, lang.mask, parent):
            self.mask = yaml[lang.mask]
        if type_is_valid(yaml[lang.vlan], int, lang.vlan, parent):
            self.vlan = yaml[lang.vlan]
        if type_is_valid(yaml[lang.interface_index], int, lang.interface_index, parent):
            self.interface_index = yaml[lang.interface_index]

class Route():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.ip], str, lang.ip, parent):
            self.ip = yaml[lang.ip]
        if type_is_valid(yaml[lang.cidr], int, lang.cidr, parent):
            self.cidr = yaml[lang.cidr]
        if type_is_valid(yaml[lang.gateway], str, lang.gateway, parent):
            self.gateway = yaml[lang.gateway]
        if type_is_valid(yaml[lang.metric], int, lang.metric, parent):
            self.metric = yaml[lang.metric]

class LinkAgg():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.id], int, lang.id, parent):
            self.id = yaml[lang.id]
        if type_is_valid(yaml[lang.number_ports], int, lang.number_ports, parent):
            self.ports_number = yaml[lang.number_ports]
        if type_is_valid(yaml[lang.key], int, lang.key, parent):
            self.key = yaml[lang.key]
        if type_is_valid(yaml[lang.enable], bool, lang.enable, parent):
            self.enable = yaml[lang.enable]
        if type_is_valid(yaml[lang.member_ports], list, lang.member_ports, parent):
            for port in yaml[lang.member_ports]:
                type_is_valid(port, str, lang.port, parent)
            self.port_members = yaml[lang.member_ports]

class VLANs():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["liste"], list, "liste", parent):
            self.vlan = [VLAN(vlan, parent + "/liste") for vlan in yaml["liste"]]
        if type_is_valid(yaml["association port/vlan"], list, "association port/vlan", parent):
            self.port_vlan_association = [PortVLANAssociation(combo, parent + "/association port/vlan") for combo in yaml["association port/vlan"]]
        if type_is_valid(yaml["association aggrégat de lien/vlan"], list, "association aggrégat de lien/vlan", parent):
            self.linkagg_vlan_association = [LinkAggVLANAssociation(combo, parent + "/association aggrégat de lien/vlan") for combo in yaml["association aggrégat de lien/vlan"]]

class VLAN():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["nom"], str, "nom", parent):
            self.name = yaml["nom"]
        if type_is_valid(yaml["identifiant"], int, "identifiant", parent):
            self.id = yaml["identifiant"]
        if type_is_valid(yaml["activé"], bool, "activé", parent):
            self.enable = yaml["activé"]

class PortVLANAssociation():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["port"], str, "port", parent):
            self.port = yaml["port"]
        if type_is_valid(yaml["tagged"], bool, "tagged", parent):
            self.tagged = yaml["tagged"]
        if type_is_valid(yaml["vlan"], int, "vlan", parent):
            self.vlan = yaml["vlan"]

class LinkAggVLANAssociation():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["identifiant"], int, "identifiant", parent):
            self.id = yaml["identifiant"]
        if type_is_valid(yaml["tagged"], bool, "tagged", parent):
            self.tagged = yaml["tagged"]
        if type_is_valid(yaml["vlan"], int, "vlan", parent):
            self.vlan = yaml["vlan"]

class NTP():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["activé"], bool, "activé", parent):
            self.enable = yaml["activé"]
        if type_is_valid(yaml["fuseau horaire"], str, "fuseau horaire", parent):
            self.time_zone = yaml["fuseau horaire"]
        if type_is_valid(yaml["serveurs"], list, "serveurs", parent):
            self.servers = [NTPServer(server, parent + "/serveurs") for server in yaml["serveurs"]]

class NTPServer():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["adresse"], str, "adresse", parent):
            self.address = yaml["adresse"]
        if type_is_valid(yaml["minpoll"], int, "minpoll", parent):
            self.minpoll = yaml["minpoll"]
        if type_is_valid(yaml["burst"], str, "burst", parent):
            self.burst = yaml["burst"]
        if type_is_valid(yaml["defaut"], bool, "defaut", parent):
            self.default = yaml["defaut"]

class PoE():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["ports avec détection de capacité"], list, "ports avec détection de capacité", parent):
            self.capacitator_detection_enabled_ports = yaml["ports avec détection de capacité"]

class AAA():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml["authentification"], dict, "authentification", parent):
            self.authentication = yaml["authentification"]
        if type_is_valid(yaml["serveurs"], dict, "serveurs", parent):
            self.servers = yaml["serveurs"]

class Authentication():
    def __init__(self, yaml, parent) -> None:
        self.access_type = {}
        for auth_type, auth_source in yaml.items():
            if type_is_valid(auth_source, [str, None], "authentification", parent):
                self.access_type[auth_type] == auth_source
        if type_is_valid(yaml["serveurs"], dict, "serveurs", parent):
            self.servers = yaml["serveurs"]

class Servers():
    def __init__(self, yaml, parent) -> None:
        pass

class ADServer():
    def __init__(self, yaml, parent) -> None:
        pass

class LoopDetection():
    def __init__(self, yaml, parent) -> None:
        pass

class STP():
    def __init__(self, yaml, parent) -> None:
        pass

class Misc():
    def __init__(self, yaml, parent) -> None:
        pass

class Switch():
    def __init__(self, yaml_file) -> None:
        with open(yaml_file) as file:
            yconf = yaml.load(file, Loader=yaml.Loader)
        
        self.sys_info = SysInfo(yconf["informations système"], "informations système")
        if type_is_valid(yconf["mot de passe admin"], [int, str], "mot de passe admin", "la racine"):
            self.admin_password = yconf["mot de passe admin"]
        self.users = [ User(user, "utilisateurs") for user in yconf["utilisateurs"]]
        self.vlan = VLANs(yconf["VLAN"], "VLAN")
        self.administrative_ip_address = [ AdministrativeIPAddress(aipa, "adresses ip d'administration") for aipa in yconf["adresses ip d'administration"]]
        self.routes = [ Route(route, "routes") for route in yconf["routes"]]
        self.link_agg = [ LinkAgg(linkagg, "aggrégation de lien") for linkagg in yconf["aggrégation de lien"]]
        self.dns = yconf["DNS"]
        self.ntp = NTP(yconf["NTP"], "NTP")
        self.poe = PoE(yconf["PoE"], "PoE")
        self.aaa = AAA(yconf["AAA"], "AAA")
        self.loopdetection = LoopDetection(yconf["détection de boucle"], "détection de boucle")
        self.stp = STP(yconf["STP"], "STP")
        self.misc = Misc(yconf["divers"], "divers")
