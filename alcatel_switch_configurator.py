from lib.lang import AlcatelSwLang
from lib.switch_class import *

import os
import sys

#file = "/home/charles/lab/alcatel_switch/template.yaml"
file = sys.argv[1]

s = Switch("/home/charles/lab/alcatel_switch/template.yaml")
s.log.print_log()
print(s.to_code().strip())
print("\x1b[46m\x1b[37m" + "-" * os.get_terminal_size()[0] + Logger._clean_end + "\x1b[0m")