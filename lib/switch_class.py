#!/usr/bin/python3

import yaml
import secrets

from lib.lang import AlcatelSwLang
from lib.misc import type_is_valid, parent_cat, AConfig
from lib.exceptions import SwitchConfigLogicError, SwitchConfigTypeError

lang = AlcatelSwLang("FR")

class Empty():
    def __init__(self, section=None):
        self.section = section
    def to_code(self):
        if self.section:
            return "! " + self.section + "\n" + lang.empty
        else:
            return lang.empty

class ListToCode(list):
    def __init__(self, l, section):
        self.section = section
        super().__init__(l)

    def to_code(self):
        aconfig = "! {}\n".format(self.section)
        for item in self:
            aconfig += item.to_code()
        return aconfig

class SysInfo():
    header = "! {} \n".format(lang.sysinfo)

    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.contact], str, lang.contact, parent):
            self.contact = yaml[lang.contact]
        if type_is_valid(yaml[lang.location], str, lang.location, parent):
            self.location = yaml[lang.location]
    
    def to_code(self):
        aconfig = AConfig(SysInfo.header)
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
        aconfig = AConfig()
        if type(self.password) is int:
            aconfig += "user {} password {}".format(self.name, secrets.token_urlsafe(self.password))
        else:
            aconfig += "user {} password {}".format(self.name, self.password)
        return aconfig

    @staticmethod
    def validate_users(users):
        u = []
        for user in users :
            if user.name in u:
                raise SwitchConfigLogicError("User \"{}\" is a duplicate.".format(user.name))
            u.append(user.name)

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

    def to_code(self):
        aconfig = AConfig()
        aconfig += "ip interface \"{}\" address {} mask {} vlan {} ifindex {}".format(
            self.name,
            self.address,
            self.mask,
            self.vlan,
            self.interface_index)
        return aconfig


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
        if type_is_valid(yaml[lang.list], list, lang.list, parent):
            self.vlan = [VLAN(vlan, parent_cat(parent, lang.list)) for vlan in yaml["liste"]]
        if type_is_valid(yaml[lang.port_vlan_association], list, lang.port_vlan_association, parent):
            self.port_vlan_association = [PortVLANAssociation(combo, parent_cat(parent, lang.port_vlan_association)) for combo in yaml[lang.port_vlan_association]]
        if type_is_valid(yaml[lang.linkagg_vlan_association], list, lang.linkagg_vlan_association, parent):
            self.linkagg_vlan_association = [LinkAggVLANAssociation(combo, parent_cat(parent, lang.linkagg_vlan_association)) for combo in yaml[lang.linkagg_vlan_association]]

class VLAN():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.name], str, lang.name, parent):
            self.name = yaml[lang.name]
        if type_is_valid(yaml[lang.id], int, lang.id, parent):
            self.id = yaml[lang.id]
        if type_is_valid(yaml[lang.enable], bool, lang.enable, parent):
            self.enable = yaml[lang.enable]

class PortVLANAssociation():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.port], str, lang.port, parent):
            self.port = yaml[lang.port]
        if type_is_valid(yaml[lang.tagged], bool, lang.tagged, parent):
            self.tagged = yaml[lang.tagged]
        if type_is_valid(yaml[lang.vlan], int, lang.vlan, parent):
            self.vlan = yaml[lang.vlan]

class LinkAggVLANAssociation():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.id], int, lang.id, parent):
            self.id = yaml[lang.id]
        if type_is_valid(yaml[lang.tagged], bool, lang.tagged, parent):
            self.tagged = yaml[lang.tagged]
        if type_is_valid(yaml[lang.vlan], int, lang.vlan, parent):
            self.vlan = yaml[lang.vlan]

class NTP():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.enable], bool, lang.enable, parent):
            self.enable = yaml[lang.enable]
        if type_is_valid(yaml[lang.timezone], str, lang.timezone, parent):
            self.time_zone = yaml[lang.timezone]
        if type_is_valid(yaml[lang.servers], list, lang.servers, parent):
            self.servers = [NTPServer(server, parent_cat(parent, lang.servers)) for server in yaml["serveurs"]]

class NTPServer():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.address], str, lang.address, parent):
            self.address = yaml[lang.address]
        if type_is_valid(yaml[lang.minpoll], int, lang.minpoll, parent):
            self.minpoll = yaml[lang.minpoll]
        if type_is_valid(yaml[lang.burst], str, lang.burst, parent):
            self.burst = yaml[lang.burst]
        if type_is_valid(yaml[lang.default], bool, lang.default, parent):
            self.default = yaml[lang.default]

class PoE():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.capacitor_detection_enabled_ports], list, lang.capacitor_detection_enabled_ports, parent):
            self.capacitator_detection_enabled_ports = yaml[lang.capacitor_detection_enabled_ports]

class AAA():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.authentication], dict, lang.authentication, parent):
            self.authentication = yaml[lang.authentication]
        if type_is_valid(yaml[lang.servers], dict, lang.servers, parent):
            self.servers = yaml[lang.servers]

class Authentication():
    def __init__(self, yaml, parent) -> None:
        self.access_type = {}
        for auth_type, auth_source in yaml.items():
            if type_is_valid(auth_source, [str, None], lang.authentication, parent):
                self.access_type[auth_type] == auth_source
        if type_is_valid(yaml[lang.servers], dict, lang.servers, parent):
            self.servers = yaml[lang.servers]

class Servers():
    def __init__(self, yaml, parent) -> None:
        pass

class ADServer():
    def __init__(self, yaml, parent) -> None:
        pass

class LoopDetection():
    def __init__(self, yaml, parent) -> None:
        if type_is_valid(yaml[lang.enable], bool, lang.enable, parent):
            self.enable = yaml[lang.enable]
        if type_is_valid(yaml[lang.transmission_timer], int, lang.transmission_timer, parent):
            self.transmission_timer = yaml[lang.transmission_timer]
        if type_is_valid(yaml[lang.autorecovery_timer], int, lang.autorecovery_timer, parent):
            self.autorecovery_timer = yaml[lang.autorecovery_timer]

class STP():
    def __init__(self, yaml, parent) -> None:
        self.by_vlan = []
        if type_is_valid(yaml[lang.by_vlan], list, lang.by_vlan, parent):
            for vlan in yaml[lang.by_vlan]:
                if type_is_valid(vlan, int, lang.vlan, parent_cat(parent, lang.by_vlan)):
                    self.by_vlan.append(vlan)

class DNS(str):
    def __init__(self, yaml, parent) -> None:
        self.parent = parent
        super().__init__()

    def __new__(cls, yaml, parent):
        return super().__new__(cls, yaml)

    def to_code(self):
        aconfig = AConfig()
        aconfig += "ip name-server {}".format(self)
        return aconfig
        

class Misc():
    def __init__(self, yaml, parent) -> None:
        pass

class Switch():
    def __init__(self, yaml_file) -> None:
        self.yaml_file = yaml_file
        with open(self.yaml_file) as file:
            self.yconf = yaml.load(file, Loader=yaml.Loader)
        self.empty = Empty()
        self._init_all()

    def _init_all(self):
        self._init_sys_info()
        self._init_users()
        self._init_vlan()
        self._init_administrative_ip_address()
        self._init_routes()
        self._init_link_agg()
        self._init_dns()
        self._init_ntp()
        self._init_poe()
        self._init_aaa()
        self._init_loop_detection()
        self._init_stp()
        self._init_misc()
    
    def _init_sys_info(self):
        try:
            self.sys_info = SysInfo(self.yconf[lang.sysinfo], lang.sysinfo)
        except KeyError as e:
            self.sys_info = Empty(section=lang.sysinfo)

    def _init_admin_password(self):
        try:
            if type_is_valid(self.yconf[lang.adminpassword], [int, str], lang.adminpassword, "/"):
                    self.admin_password = self.yconf[lang.adminpassword]
        except KeyError:
            self.admin_password = Empty(section=lang.adminpassword)

    def _init_users(self):
        try:
            self.users = ListToCode([ User(user, lang.users) for user in self.yconf[lang.users]], lang.users)
            User.validate_users(self.users)
        except SwitchConfigLogicError as e:
            print("Error while parsing the \"{}\" section".format(lang.users))
            print(e.message)
        except KeyError:
            self.users = ListToCode([self.empty], lang.users)
    
    def _init_vlan(self):
        try:
            self.vlan = VLANs(self.yconf["VLAN"], "VLAN")
        except KeyError:
            self.vlan = Empty(section="VLAN")

    def _init_administrative_ip_address(self):
        try:
            self.administrative_ip_address = ListToCode([ AdministrativeIPAddress(aipa, lang.admin_ip_address) for aipa in self.yconf[lang.admin_ip_address]], lang.admin_ip_address)
        except KeyError:
            self.administrative_ip_address = ListToCode([self.empty], lang.admin_ip_address)

    def _init_routes(self):
        try:
            self.routes = ListToCode([ Route(route, lang.routes) for route in self.yconf[lang.routes]], lang.routes)
        except KeyError:
            self.routes = ListToCode([self.empty], lang.routes)

    def _init_link_agg(self):
        try:
            self.link_agg = ListToCode([ LinkAgg(linkagg, lang.linkagg) for linkagg in self.yconf[lang.linkagg]], lang.linkagg)
        except KeyError:
            self.linkagg = ListToCode([self.empty], lang.linkagg)

    def _init_dns(self):
        try:
            self.dns = ListToCode([ DNS(dns, "DNS") for dns in self.yconf["DNS"]], "DNS")
        except KeyError:
            self.dns = ListToCode([self.empty], lang.dns)

    def _init_ntp(self):
        try:
            self.ntp = NTP(self.yconf["NTP"], "NTP")
        except KeyError:
            self.ntp = Empty(section="NTP")
    
    def _init_poe(self):
        try:
            self.poe = PoE(self.yconf["PoE"], "PoE")
        except KeyError:
            self.poe = Empty(section="PoE")
    
    def _init_aaa(self):
        try:
            self.aaa = AAA(self.yconf["AAA"], "AAA")
        except KeyError:
            self.aaa = Empty(section="AAA")
    
    def _init_loop_detection(self):
        try:
            self.loopdetection = LoopDetection(self.yconf[lang.loop_detection], lang.loop_detection)
        except KeyError:
            self.loopdetection = Empty(section=lang.loop_detection)
    
    def _init_stp(self):
        try:
            self.stp = STP(self.yconf["STP"], "STP")
        except KeyError:
            self.stp = Empty(section="STP")
    
    def _init_misc(self):
        try:
            self.misc = Misc(self.yconf[lang.misc], lang.misc)
        except KeyError:
            self.misc = Empty(section=lang.misc)

    def to_code(self):
        aconfig = AConfig(lang.intro.format(SRC_FILE=self.yaml_file))
        aconfig += self.sys_info.to_code()
        aconfig += self.users.to_code()
        aconfig += self.dns.to_code()
        aconfig += self.administrative_ip_address.to_code()
        return aconfig
