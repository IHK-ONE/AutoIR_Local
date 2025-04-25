# -*- coding: UTF-8 -*-
from core.functions import *


def RookitExtract():
    result = exec_command('cp extensions/rkhunter.gz /tmp/rkhunter.gz && cd /tmp && tar -xf /tmp/rkhunter.gz && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install')
    if result['status'] and result['result']:
        print(f'[success] {get_color("rkhunter rookit检测工具上传安装成功，需要手动执行命令", "green")}: \n\trkhunter --check') if "complete" in result['result'] else None