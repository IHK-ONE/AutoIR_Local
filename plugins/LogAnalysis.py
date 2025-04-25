# -*- coding: UTF-8 -*-
from core.functions import *

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

class LogAnalysis:
    def __init__(self):
        self.request_success = {}
        self.request_jump = {}
        self.request_others = {}
        self.user_agents = []

        self.check_log()
        self.check_login_success()
        self.check_login_fail()


    def check_log(self):
        info = get_color('apache2 日志分析', 'green')
        output = ''
        path = '/var/log/apache2/access.log'
        check = input(f'[!] 请输入 web 日志路径，输入 [Enter] 则为默认 {path}: ')
        if check.strip():
            path = check.strip()

        if os.path.exists(path):
            try:
                for num, match in enumerate(pattern.finditer(open(path).read())):
                    request = match.groupdict()
                    status = request['status']
                    user_agent = request['user_agent']

                    if status == '200' and len(request['path']) != 1:  # 统计成功访问页面
                        self.request_success[num] = request
                    elif status == '302':  # 统计跳转页面
                        self.request_jump[num] = request
                    else:  # 其他
                        self.request_others[num] = request

                    if user_agent not in self.user_agents:
                        self.user_agents.append(user_agent)

                output += get_color('成功访问 IP 统计', 'green') + '\n'
                for ip, count in get_counter([request['ip'] for request in self.request_success.values()]).items():
                    output += f'\tip: {ip:<20}\tcount: {count}\n'

                output +=  get_color('\n跳转访问 IP 统计', 'green') + '\n'
                for ip, count in get_counter([request['ip'] for request in self.request_jump.values()]).items():
                    output += f'\tip: {ip:<20}\tcount: {count}\n'

                output +=  get_color('\n失败访问 IP 统计', 'green') + '\n'
                for ip, count in get_counter([request['ip'] for request in self.request_others.values()]).items():
                    output += f'\tip: {ip:<20}\tcount: {count}\n'

                output +=  get_color('\n访问 User-Agent 统计', 'green') + '\n'
                for user_agent in sorted(self.user_agents):
                    output += f'\tUser-Agent: {user_agent:<20}\n'

                output +=  get_color('\n成功访问 请求统计', 'green') + '\n'
                for request in self.request_success.values():
                    output += f'\tip: {request["ip"]:<20}\turi: {request["path"]:<50}\tuser agent: {request["user_agent"]}\n'

                output +=  get_color('\n跳转访问 请求统计', 'green') + '\n'
                for request in self.request_jump.values():
                    output += f'\tip: {request["ip"]:<20}\turi: {request["path"]:<50}\tuser agent: {request["user_agent"]}\n'

            except:
                pass
            get_output(info, output)

    def check_login_success(self):
        info = get_color('登入成功日志排查', 'green')
        output = ''
        login_success = {}

        result = exec_command('last')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                line = line.strip()
                try:
                    parts = re.split(r'\s+', line)
                    ip = parts[2]
                    if ip in login_success:
                        login_success[ip] += 1
                    else:
                        login_success[ip] = 1
                except:
                    pass
        for ip, count in login_success.items():
            if '.' in ip:
                output += f'ip: {ip:<20}\tcount: {count:<5}\t[!] {get_color("爆破登入 IP")}\n'
        get_output(info, output)

    def check_login_fail(self):
        info = get_color('登入失败日志排查', 'green')
        output = ''
        login_fail = {}

        result = exec_command('lastb')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                line = line.strip()
                try:
                    parts = re.split(r'\s+', line)
                    ip = parts[2]
                    if ip in login_fail:
                        login_fail[ip] += 1
                    else:
                        login_fail[ip] = 1
                except:
                    pass
        for ip, count in login_fail.items():
            if '.' in ip:
                output += f'ip: {ip:<20}\tcount: {count:<5}\t[!] {get_color("爆破登入 IP")}\n'
        get_output(info, output)
