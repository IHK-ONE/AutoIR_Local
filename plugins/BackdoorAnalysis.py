# -*- coding: UTF-8 -*-
from core.functions import *

class BackdoorAnalysis:
    def __init__(self):
        self.check_ld_so_preload()
        self.check_cron()
        self.check_ssh()
        self.check_ssh_wrapper()
        self.check_inetd()
        self.check_xinetd()
        self.check_profile()
        self.check_rc()
        self.check_startup()
        self.check_setuid()

    def check_malicious_content(self, file_path):
        output = ''
        try:
            for line in open(file_path).readlines():
                if not line.startswith('#'):
                    malicious = check_safe_local(line.strip())
                    if malicious:
                        output += f'file: {file_path:<40}\tcontent: {malicious:<40}\t[!] {get_color("恶意命令执行")}\n'
        except:
            pass
        return output

    def check_ld_so_preload(self):
        info = get_color('/etc/ld.so.preload 后门排查', 'green')
        output = ''
        try:
            for line in open('/etc/ld.so.preload').readlines():
                if line and not line.startswith('#'):
                    output += f'{line.strip():<50}\t[!] {get_color("ld.so.preload 后门！", "red")}\n'
        except:
            pass
        get_output(info, output)

    def check_cron(self):
        info = get_color('计划任务后门排查', 'green')
        output = ''

        cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly', '/etc/cron.monthly']
        for cron_dir in cron_dirs:
            try:
                for file in os.listdir(cron_dir):
                    output += self.check_malicious_content(f'{cron_dir}/{file}')
            except:
                pass
        get_output(info, output)

    def check_ssh(self):
        info = get_color('/usr/sbin/sshd 软连接后门排查', 'green')
        output = ''
        try:
            output += f'content: {os.readlink("/usr/sbin/sshd"):<50}\t[!] {get_color("sshd 已被劫持", "red")}\n'
        except:
            pass

        get_output(info, output)

    def check_ssh_wrapper(self):
        info = get_color('/usr/sbin/sshd ssh wrapper 后门排查', 'green')
        output = ''

        result = exec_command('strings /usr/sbin/sshd')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                malicious = check_safe_local(line.strip())
                if malicious:
                    if '\033' in malicious:
                        output += f'file: {"/usr/sbin/sshd":<40}\tcontent: {malicious}\t {get_color("恶意 shell 命令", "red")}\n'
                    else:
                        output += f'file: {"/usr/sbin/sshd":<40}\tcontent: {malicious}\t[!] {get_color("ssh wrapper 劫持")}\n'

        get_output(info, output)

    def check_inetd(self):
        info = get_color('/etc/inetd.conf 后门排查', 'green')
        output = self.check_malicious_content('/etc/inetd.conf')
        get_output(info, output)

    def check_xinetd(self):
        info = get_color('xinetd 后门排查', 'green')
        output = ''
        try:
            for file in os.listdir('/etc/xinetd.conf'):
                output += self.check_malicious_content(f'/etc/xinetd.conf/{file}')
        except:
            pass
        get_output(info, output)

    def check_setuid(self):
        info = get_color('SUID 后门排查', 'green')
        output = ''

        result = exec_command("find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                output += f'command {line.strip():<50}\t[!] {get_color("SUID 后门", "red")}\n'

        get_output(info, output)

    def check_startup(self):
        info = get_color('启动项排查', 'green')
        output = ''

        init_paths = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system', '/usr/local/etc/rc.d']
        init_files = ['/etc/rc.local', '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab']

        for path in init_paths:
            try:
                for file in os.listdir(path):
                    output += self.check_malicious_content(f'{path}/{file}')
            except:
                pass

        for file in init_files:
            output += self.check_malicious_content(f'{file}')

        get_output(info, output)

    def check_profile(self):
        info = get_color('/etc/profile.d 后门排查', 'green')
        output = ''
        try:
            for file in os.listdir('/etc/profile.d'):
                output += self.check_malicious_content(f'/etc/profile.d/{file}')
        except:
            pass
        get_output(info, output)


    def check_rc(self):
        info = get_color('bashrc 等初始化排查', 'green')
        output = ''
        user_list = []

        init_paths = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc', '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
        init_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

        for path in init_paths:
            output += self.check_malicious_content(path)

        try:
            user_list = os.listdir('/home')
        except:
            pass

        for user in user_list:
            for file in init_files:
                output += self.check_malicious_content(f'/home/{user}/{file}')

        get_output(info, output)