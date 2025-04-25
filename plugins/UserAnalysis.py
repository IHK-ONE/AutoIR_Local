# -*- coding: UTF-8 -*-
from core.functions import *

'''
# 恶意用户排查
  1. 排查 home 下用户
  2. 排查 /etc/passwd 下，拥有 shell 权限、root 权限、特殊权限的用户
  3. 排查 /etc/shadow 下，空口令用户（无密码登录用户）
  4. 排查 sudo 中权限异常用户
  5. 排查 拥有 authorized_keys 免密登录用户
'''


class UserAnalysis:
    def __init__(self):
        self.user_list = []
        self.group_list = {}

        self.check_home()
        self.check_history()
        self.check_ssh_keys()
        self.check_passwd()
        self.check_shadow()
        self.check_sudoers()

    def check_home(self):
        info = get_color('home 目录用户', 'green')
        if os.path.exists(f'/home'):
            self.user_list = os.listdir('/home')
        get_output(info, '\n'.join(self.user_list))

    def check_history(self):
        info = get_color('home/.bash_history 排查', 'green')
        output = []

        # 检查 root 用户的 bash_history
        if os.path.exists('/root/.bash_history'):
            output.append(f'{"/root/.bash_history":<50}\t[!] {get_color("存在 bash_history")}')

        # 检查其他用户的 bash_history
        for user in self.user_list:
            if os.path.exists(f'/home/{user}/.bash_history'):
                output.append(f'{f"/home/{user}/.bash_history":<50}\t[!] {get_color("存在 bash_history")}')

        get_output(info, '\n'.join(output))

    def check_passwd(self):
        info = get_color('/etc/passwd 异常用户排查', 'green')
        output = []

        if os.path.exists('/etc/passwd'):
            try:
                for line in open('/etc/passwd').readlines():
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        user_name, user_uid, user_gid, _, _, _, user_shell = parts
                        issues = []
                        if ('nologin' not in user_shell) and (user_name != 'root'):
                            if "sh" in user_shell:
                                issues.append(get_color('拥有 shell 权限 [拥有系统 shell]', 'red'))
                            else:
                                issues.append(get_color('拥有 shell 权限 [请检测 shell]'))
                        if user_uid == '0' and user_name != 'root':
                            issues.append(get_color('root 标识用户', 'red'))
                        if user_gid == '0' and user_name != 'root':
                            issues.append(get_color('特权用户', 'red'))
                        if issues:
                            output.append(f'{"user: " + user_name:<20}\t{"shell: " + user_shell:<20}\t[!] {"、".join(issues)}')
            except:
                pass
        get_output(info, '\n'.join(output))


    def check_ssh_keys(self):
        info = get_color('SSH authorized_keys 排查', 'green')
        output = []

        # 检查 root 用户的 authorized_keys
        if os.path.exists('/root/.ssh/authorized_keys'):
            try:
                users = ', '.join(get_user(open('/root/.ssh/authorized_keys').read()))
                output.append(f'{"/root/.ssh/authorized_keys":<40}\t{"user list: " + get_color(users, "red"):<20}\t[!] {get_color("存在 SSH authorized_keys", "red")}')
            except:
                pass

        # 检查其他用户的 authorized_keys
        for user in self.user_list:
            if os.path.exists(f'/home/{user}/.ssh/authorized_keys'):
                try:
                    users = ', '.join(get_user(open(f'/home/{user}/.ssh/authorized_keys').read()))
                    output.append(f'{f"/home/{user}/.ssh/authorized_keys":<40}\t{"user list: " + get_color(users, "red"):<20}\t[!] {get_color("存在 SSH authorized_keys", "red")}')
                except:
                    pass

        get_output(info, '\n'.join(output))

    def check_shadow(self):
        info = get_color('/etc/shadow 异常用户排查', 'green')
        output = []

        if os.path.exists('/etc/shadow'):
            try:
                for line in open('/etc/shadow').readlines():
                    parts = line.strip().split(':')
                    user, hashcode = parts[0], parts[1]
                    output.append(f'{"user: " + user:<50}\t[!] {get_color("空口令账户")}') if not hashcode else None
            except:
                pass
        get_output(info, '\n'.join(output))

    def check_sudoers(self):
        info = get_color('sudo 用户权限排查', 'green')
        output = []

        if os.path.exists('/etc/sudoers'):
            self.get_group()
            try:
                for line in open('/etc/sudoers').readlines():
                    line = line.strip()
                    if ('ALL=(ALL)' in line or 'ALL=(root)' in line) and not line.startswith('#'):
                        parts = line.split()
                        user_or_group = parts[0]

                        if user_or_group.startswith('%'):  # 组
                            group_name = user_or_group[1:]
                            users_in_group = self.group_list.get(group_name, [])
                            output.append(f'{"group: " + group_name:<30}\t{"user: " + ", ".join(users_in_group):<20}\t[!] {get_color("sudo 权限组异常", "red")}')
                        else:
                            output.append(f'{"user: " + user_or_group:<50}\t[!] {get_color("sudo 权限组异常", "red")}')
            except:
                pass
        get_output(info, '\n'.join(output))

    def get_group(self):
        if os.path.exists('/etc/group'):
            try:
                for line in open('/etc/group').readlines():
                    parts = line.strip().split(':')
                    group_name, _, _, users = parts
                    self.group_list[group_name] = [user.strip() for user in users.split(',') if user.strip()]
            except:
                pass
