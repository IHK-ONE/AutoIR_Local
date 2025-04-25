# -*- coding: UTF-8 -*-
from core.functions import *

'''
# HijackAnalysis 劫持排查
  环境变量劫持
'''

class HijackAnalysis:
    def __init__(self):
        self.hijack = False
        self.hijack_list = []
        self.output = []
        self.check_hijack()

    def check_export(self, filename, data):
        try:
            export_list = re.findall(r'export (.*)=(.*)', data)
            for key, value in export_list:
                if key in ('PATH', 'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH', 'PROMPT_COMMAND') and value != '"$PATH:${snap_bin_path}"':
                    self.hijack_list.append(key)
                    status = f'[+] {get_color(key + " 环境变量劫持", "red")}'
                else:
                    status = f'[!] {get_color("环境变量劫持")}'
                self.output.append(f'{"filename: " + filename:<50}\t{"export" + key + "=" + value:<70}\t{status:<30}')
        except:
            pass

    def check_hijack(self):
        info = get_color('环境变量劫持排查：', 'green') + '\n需要手动排查，部分恶意脚本可能会通过调用环境变量进行绕过'

        # 常规目录环境变量排查
        common_files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc', '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
        home_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

        # 处理常规文件
        for file in common_files:
            if os.path.exists(file):
                try:
                    self.check_export(file, open(file, 'r').read())
                except:
                    pass

        if os.path.exists('/home'):
            user_list = os.listdir('/home')
            for user in user_list:
                for file in home_files:
                    try:
                        self.check_export(f'/etc/profile.d/{file}', open(f'/home/{user}/{file}', 'r').read()) if os.path.exists(file) else None
                    except:
                        pass

        # 处理 /etc/profile.d/ 目录下的文件
        if os.path.exists(f'/etc/profile.d/'):
            for file in os.listdir('/etc/profile.d/'):
                try:
                    self.check_export(f'/etc/profile.d/{file}', open(f'/etc/profile.d/{file}', 'r').read())
                except:
                    pass

        get_output(info, '\n'.join(self.output))
        if self.hijack_list and input(get_color('检测到当前环境变量已被劫持，是否继续？继续可能会有报错产生 [enter/n]', 'red')) == 'n':
            exit(0)
