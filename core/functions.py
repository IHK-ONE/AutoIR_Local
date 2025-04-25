# -*- coding: UTF-8 -*-
import os
import re
import urllib
import hashlib
import subprocess


def get_color(string, color='yellow'):
    # print("\033[显示方式;前景颜色;背景颜色m strings \033[0m")
    if color == 'red':
        return f'\033[0;31m{string}\033[0m'
    elif color == 'green':
        return f'\033[0;32m{string}\033[0m'
    elif color == 'yellow':
        return f'\033[0;33m{string}\033[0m'

def get_counter(data_list):
    data_lists = {}
    for item in data_list:
        if item not in data_lists:
            data_lists[item] = 1
        else:
            data_lists[item] += 1
    return data_lists

def get_file_list(files):
    # 将 ls -al 的数据转换为列表
    file_list = {}
    files = files.splitlines()[1:]
    for i in range(len(files)):
        file = files[i].strip()
        parts = re.split(r'\s+', file.strip())
        perm = parts[0].strip('.').strip('+')  # 文件权限
        link = parts[1]  # 硬链接数
        owner = parts[2]  # 文件拥有者
        group = parts[3]  # 所在用户组
        size = parts[4]  # 文件大小
        filename = ' '.join(_ for _ in parts[8:])  # 文件名
        if filename not in ['.', '..']:
            file_list[i] = {'perm': perm, 'link': link, 'owner': owner, 'group': group, 'size': size, 'filename': filename}
    return file_list

def exec_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_output = result.stdout.strip()
        stderr_output = result.stderr.strip()

        output = {'status': False, 'result': stderr_output}
        if stdout_output:
            output.update({'status': True, 'result': stdout_output})

        return output
    except Exception as e:
        return {'status': False, 'result': str(e)}

def check_keyword_filter(content):
    # 对关键字进行标红
    for token in ["flag{", "flag", "666c6167", "f1ag", "fl4g", "Zmxh", "&#102", "MZWGC", "102 108 97 103", "1100110", "ctf", "504b0304", "key", "464C4147", "pass", "select", "/bin/bash", " bash ", "/bin/sh", " .sh ", " sh "]:
        if token in content:
            content = content.replace(token, get_color(token, 'red'))
    return content


def get_output(info, output):
    # 格式化输出最终，同时该方法保留，不在类函数直接 print 便于后续修改为 return 并接入第三方平台（web端开发中）
    if len(output):
        formatted_info = f'[success] {info} :\n'
        formatted_output = ''

        for line in output.splitlines():
            line = check_keyword_filter(line.strip())
            formatted_output += f'\t{line}\n'

        print(formatted_info + formatted_output)  # 格式化输出模式
    else:
        print(f'{"[success] " + info:<60}\t[-] {get_color("safe 无风险", "green")}\n')


def get_user(content):
    return [line.strip().split()[-1] for line in content.splitlines() if line.strip()]


def check_safe_local(content):
    # 检测恶意 shell
    # Author：咚咚呛
    # Github：https://github.com/grayddq/GScan

    try:
        if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (('exec ' in content) and ('socket' in content)) or ('curl ' in content) or ('wget ' in content) or ('lynx ' in content) or ('bash -i' in content))) or (".decode('base64')" in content) or ("exec(base64.b64decode" in content):
            return content
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content
        elif (('wget ' in content) or ('curl ' in content)) and ((' -O ' in content) or (' -s ' in content)) and (' http' in content) and (('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or ('bash ' in content)):
            return content
        return ''
    except:
        return ''
