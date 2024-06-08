from lib.lang import AlcatelSwLang
from lib.switch_class import *

file = "/home/charles/lab/alcatel_switch/template.yaml"

s = Switch("/home/charles/lab/alcatel_switch/template.yaml")

print(s.to_code())
