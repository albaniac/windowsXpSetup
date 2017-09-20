#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# File: windowsxpsetup.py
# Copyright (c) 2010 by Costas Tyfoxylos
#
# GNU General Public Licence (GPL)
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
#


import sys
import re
import os
import time
from subprocess import call, Popen, PIPE
from netaddr import IPRange, IPAddress

from win32com.client import GetObject
from _winreg import (OpenKey,
                     ConnectRegistry,
                     QueryValueEx,
                     SetValueEx,
                     CloseKey,
                     CreateKey,
                     DeleteValue,
                     HKEY_LOCAL_MACHINE,
                     HKEY_CURRENT_USER,
                     KEY_ALL_ACCESS,
                     KEY_SET_VALUE,
                     REG_SZ,
                     REG_DWORD,
                     REG_EXPAND_SZ)

from win32net import (NetUserAdd,
                      NetLocalGroupAddMembers,
                      NetLocalGroupDelMembers,
                      NetUserGetInfo,
                      NetUserSetInfo)
from win32print import EnumPrinterDrivers
from ntsecuritycon import (TOKEN_ADJUST_PRIVILEGES,
                           TOKEN_QUERY,
                           SE_PRIVILEGE_ENABLED,
                           SE_SHUTDOWN_NAME)
from win32netcon import RESOURCETYPE_DISK as DISK
import ctypes
import win32security
import win32api
import win32con
import win32wnet
import win32netcon
# import pywintypes
import wmi
import win32gui

__author__ = '''Costas Tyfoxylos <costas.tyf@gmail.com>'''
__docformat__ = '''plaintext'''
__date__ = '''07/10/2010'''


class WindowsXp(object):
    def __init__(self):
        pass

    @staticmethod
    def change_key(cd_key):
        cd_key = cd_key.upper()
        key_pattern = re.compile(("[A-Z0-9]{5}-"
                                  "[A-Z0-9]{5}-"
                                  "[A-Z0-9]{5}-"
                                  "[A-Z0-9]{5}-"
                                  "[A-Z0-9]{5}"))
        if not key_pattern.match(cd_key):
            print("The CD Key seems invalid.\nPlease input a key in the form "
                  "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
            return False
        cd_key = cd_key.replace("-", "")
        reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                          (r'SOFTWARE\Microsoft\Windows NT'
                           '\CurrentVersion\WPAEvents'),
                          0,
                          KEY_ALL_ACCESS)
        try:
            _ = QueryValueEx(reg_key, 'OOBETimer')[0]  # noqa
            DeleteValue(reg_key, 'OOBETimer')
        except WindowsError:
            pass
        win = wmi.WMI()
        ret_code = None
        for instance in win.win32_WindowsProductActivation():
            ret_code = instance.SetProductKey(cd_key)[0]
        return not ret_code

    @staticmethod
    def rename(pc_name):
        result = False
        win = wmi.WMI()
        for instance in win.Win32_ComputerSystem():
            result = instance.Rename(pc_name)
        return not result

    @staticmethod
    def update_organization_info(info):
        reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                          r'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                          0,
                          KEY_SET_VALUE)
        SetValueEx(reg_key, 'RegisteredOrganization', 0, REG_SZ, info)
        CloseKey(reg_key)

    @staticmethod
    def update_owner_info(info):
        reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                          r'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                          0,
                          KEY_SET_VALUE)
        SetValueEx(reg_key, 'RegisteredOwner', 0, REG_SZ, info)
        CloseKey(reg_key)

    @staticmethod
    def create_user(name, full_name, password):
        user_data = {'name': name,
                     'full_name': full_name,
                     'password': password,
                     'flags': win32netcon.UF_NORMAL_ACCOUNT |
                              win32netcon.UF_SCRIPT |
                              win32netcon.UF_DONT_EXPIRE_PASSWD |
                              win32netcon.UF_PASSWD_CANT_CHANGE,
                     'priv': win32netcon.USER_PRIV_USER,
                     'home_dir': os.path.join(r"C:\Documents and Settings",
                                              name)}
        NetUserAdd(None, 1, user_data)

    @staticmethod
    def rename_administrator_account(new_name, password):
        old_name = "Administrator"
        info = NetUserGetInfo(None, old_name, 3)
        info['password'] = password
        NetUserSetInfo(None, old_name, 3, info)
        computer_name = '.'
        computer = GetObject('WinNT://{}'.format(computer_name))
        user = GetObject(('WinNT://{computer}/'
                          '{name},user').format(computer=computer_name,
                                                name=old_name))
        _ = computer.MoveHere(user.ADsPath, new_name)  # noqa
        reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                          (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                           r'\Winlogon\SpecialAccounts\UserList'),
                          0,
                          KEY_SET_VALUE)
        SetValueEx(reg_key, new_name, 0, REG_DWORD, 0)
        CloseKey(reg_key)

    def create_tcp_port(self, port_name, ip_address, port=9100):
        base_path = (r'SYSTEM\ControlSet001\Control'
                     r'\Print\Monitors\Standard TCP/IP Port\Ports')
        reg_key = OpenKey(HKEY_LOCAL_MACHINE, base_path, 0, KEY_ALL_ACCESS)
        try:
            _ = QueryValueEx(reg_key, 'StatusUpdateEnabled')[0]  # noqa
        except WindowsError:
            SetValueEx(reg_key, 'StatusUpdateEnabled', 0, REG_DWORD, 1)
        try:
            _ = QueryValueEx(reg_key, 'StatusUpdateInterval')[0]  # noqa
        except WindowsError:
            SetValueEx(reg_key, 'StatusUpdateInterval', 0, REG_DWORD, 10)
        CloseKey(reg_key)
        try:
            _ = OpenKey(HKEY_LOCAL_MACHINE,
                        r'{base}\{port}'.format(base=base_path,
                                                port=port_name),
                        0,
                        KEY_ALL_ACCESS)  # noqa
            print "There is already a port named :" + port_name
            return False
        except WindowsError:
            try:
                reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                                  base_path,
                                  0,
                                  KEY_ALL_ACCESS)
                CreateKey(reg_key, port_name)
                CloseKey(reg_key)
                reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                                  base_path + '\\' + port_name,
                                  r'{base}\{port}'.format(base=base_path,
                                                          port=port_name),
                                  0,
                                  KEY_ALL_ACCESS)
                SetValueEx(reg_key, 'Protocol', 0, REG_DWORD, 1)
                SetValueEx(reg_key, 'Version', 0, REG_DWORD, 1)
                SetValueEx(reg_key, 'HostName', 0, REG_SZ, '')
                SetValueEx(reg_key, 'IPAddress', 0, REG_SZ, ip_address)
                SetValueEx(reg_key, 'HWAddress', 0, REG_SZ, '')
                SetValueEx(reg_key, 'PortNumber', 0, REG_DWORD, port)
                SetValueEx(reg_key, 'SNMP Community', 0, REG_SZ, 'public')
                SetValueEx(reg_key, 'SNMP Enabled', 0, REG_DWORD, 1)
                SetValueEx(reg_key, 'SNMP Index', 0, REG_DWORD, 1)
                result = self.__restart_win_service('Spooler')
                return result
            except Exception:  # noqa
                return False

    def create_rpt_port(self, name='RPT1:'):
        base_path = (r'SYSTEM\ControlSet001\Control'
                     r'\Print\Monitors\Redirected Port')
        port_name = name
        try:
            _ = OpenKey(HKEY_LOCAL_MACHINE,
                        r'{base}\Ports\{port}'.format(base=base_path,
                                                      port=port_name),
                        0,
                        KEY_ALL_ACCESS)
            print "There is already a port named :{}".format(port_name)
            return False
        except WindowsError:
            try:
                reg_key = OpenKey(HKEY_LOCAL_MACHINE,
                                  base_path, 0, KEY_ALL_ACCESS)
                new_key = CreateKey(reg_key, 'Ports')
                reg_key = CreateKey(new_key, port_name)
                SetValueEx(reg_key, 'Description', 0, REG_SZ, 'Redirected Port')
                SetValueEx(reg_key, 'Command', 0, REG_SZ, '')
                SetValueEx(reg_key, 'Arguments', 0, REG_SZ, '')
                SetValueEx(reg_key, 'Printer', 0, REG_SZ, '')
                SetValueEx(reg_key, 'Output', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'Description', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'ShowWindow', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'RunUser', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'Delay', 0, REG_DWORD, 300)
                SetValueEx(reg_key, 'LogFileUse', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'LogFileDebug', 0, REG_DWORD, 0)
                SetValueEx(reg_key, 'PrintError', 0, REG_DWORD, 0)
                result = self.__restart_win_service('Spooler')
                return result
            except Exception:  # noqa
                return False

    @staticmethod
    def __restart_win_service(service_name):
        start = stop = None
        win = wmi.WMI()
        for service in win.Win32_Service(Name=service_name):
            stop, = service.StopService()
            start, = service.StartService()
        time.sleep(4)
        return not any([stop, start])

    @staticmethod
    def install_driver(model_driver_name, inf_file=None):
        inf_file = inf_file or os.path.join(os.environ['windir'],
                                            'inf',
                                            'ntprint.inf')
        cmd = [
            "rundll32",
            "printui.dll,PrintUIEntry",
            "/ia",
            "/m", model_driver_name,
            "/f", inf_file,
            "/u"]
        return not call(cmd)

    @staticmethod
    def is_printer_driver_installed(driver_name):
        return driver_name in [driver['Name']
                               for driver in EnumPrinterDrivers()]

    def install_printer(self,
                        printer_name,
                        model_driver_name,
                        port_name=False,
                        port_ip=False,
                        inf_file=False):
        if not self.is_printer_driver_installed(model_driver_name):
            if not self.install_driver(model_driver_name, inf_file):
                print ("Something went wrong with the driver installation. "
                       "Quiting..")
                return False
        if port_name:
            try:
                external_ip = IPAddress(port_ip)
                port_ip = str(external_ip)
                port_created = self.create_tcp_port(port_name, port_ip)
            except Exception:  # noqa
                print ('There is a problem with the ip given for the printer '
                       'port. Quiting..')
                return False
        else:
            port_created = self.create_rpt_port()
            port_name = "RPT1:"
        if not port_created:
            print "There was a problem creating the port. Quiting.."
            return False
        cmd = [
            "rundll32",
            "printui.dll,PrintUIEntry",
            "/if",
            "/r", port_name,
            "/b", printer_name,
            "/f", os.path.join(os.environ['windir'], 'inf', 'ntprint.inf'),
            "/m", model_driver_name,
            "/u",
            "/z"]
        return not call(cmd)

    def fax_setup(self, username, password, email, hostname, modem_list=None):
        command = r'c:\Program Files\Python\pythonw.exe'
        arguments = r'"c:\Program files\pyla\pyla.py" -i'
        base_path = (r'SYSTEM\ControlSet001\Control'
                     r'\Print\Monitors\Redirected Port\Ports\RPT1:')
        try:
            reg_key = OpenKey(HKEY_LOCAL_MACHINE, base_path, 0, KEY_ALL_ACCESS)
        except WindowsError:
            if not self.create_rpt_port():
                print "RPT1: port not found and unable to create one. Quiting.."
                return False
            reg_key = OpenKey(HKEY_LOCAL_MACHINE, base_path, 0, KEY_ALL_ACCESS)
        try:
            SetValueEx(reg_key, 'Command', 0, REG_SZ, command)
            SetValueEx(reg_key, 'Arguments', 0, REG_SZ, arguments)
            CloseKey(reg_key)
        except WindowsError:
            print "Problem creating port command and arguments. Quiting.."
            return False
        try:
            conf_text = file(
                    r'c:\Program Files\Pyla\profiles\pylarc.default',
                    'rb').read()
            conf_text = conf_text.replace('username=', 'username=' + username)
            conf_text = conf_text.replace('password=', 'password=' + password)
            conf_text = conf_text.replace(
                    'emailaddress=', 'emailaddress=' + email)
            conf_text = conf_text.replace('faxhost=', 'faxhost=' + hostname)
            if modem_list:
                conf_text = conf_text.replace(
                        'modemlist=', 'modemlist=' + modem_list + '\n')
            conf_file = file(
                    r'c:\Program Files\Pyla\profiles\pylarc.default', 'wb')
            conf_file.write(conf_text)
            conf_file.close()
            return True
        except Exception:  # noqa
            print "Something went wrong with the pyla profile file. Quiting.."
            return False

    @staticmethod
    def __get_binary_path(name):
        binary = ''
        if sys.platform == 'linux2':
            binary = Popen('which %s' % name, stdout=PIPE,
                           shell=True).stdout.read().strip()
        elif sys.platform == 'win32':
            if name == 'soffice':
                key = OpenKey(HKEY_LOCAL_MACHINE,
                              (r'SOFTWARE\OpenOffice.org'
                               r'\Layers\OpenOffice.org\3'),
                              0,
                              KEY_ALL_ACCESS)
                sub_key = QueryValueEx(key, "OFFICEINSTALLLOCATION")[0]
                binary = os.path.join(sub_key, 'program', 'soffice.exe')
            elif name == 'firefox' or name == 'thunderbird':
                key = OpenKey(HKEY_LOCAL_MACHINE,
                              r'Software\Mozilla\Mozilla ' + name.capitalize(),
                              0,
                              KEY_ALL_ACCESS)
                sub_key = QueryValueEx(key, "CurrentVersion")[0]
                key = OpenKey(HKEY_LOCAL_MACHINE,
                              r'Software\Mozilla\Mozilla ' + name.capitalize()
                              + '\\' + sub_key + '\\Main',
                              0, KEY_ALL_ACCESS)
                binary = QueryValueEx(key, "PathToExe")[0]
        if binary:
            return binary
        else:
            print "Binary not found."
            return False

    def set_mozilla_profile(self, software, drive_letter):
        child_pid = ''
        if not os.path.isdir(drive_letter):
            print(("{} doesn't seem like a valid drive. "
                   "Quiting..").format(drive_letter))
            return False
        binary = self.__get_binary_path(software)
        cmd = [binary,
               "-CreateProfile",
               r"Default {drive}\.{software}".format(drive=drive_letter,
                                                     software=software)]
        ret_code = call(cmd)
        if ret_code != 0:
            return False
        cmd2 = [binary]
        if software == 'firefox':
            cmd2.append('-setDefaultBrowser')
        elif software == 'thunderbird':
            cmd2.append('-setDefaultMail')
        proc = Popen(cmd2)
        time.sleep(20)
        c = wmi.WMI()
        for process in c.Win32_Process(["ProcessID"], ParentProcessID=proc.pid):
            child_pid = process.ProcessID
        if not child_pid:
            child_pid = proc.pid
        PROCESS_TERMINATE = 1  # noqa
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE,
                                                    False,
                                                    child_pid)
        ctypes.windll.kernel32.TerminateProcess(handle, -1)
        ctypes.windll.kernel32.CloseHandle(handle)

    def set_ooo_profile(self, drive_letter):
        if not os.path.isdir(drive_letter):
            print(("{} doesn't seem like a valid drive. "
                   "Quiting..").format(drive_letter))
            return False
        binary = self.__get_binary_path('soffice')
        cmd = [binary,
               ('-env:UserInstallation='
                'file:///{drive}/.openoffice.org/3'.format(drive=drive_letter))]
        proc = Popen(cmd)
        time.sleep(20)
        c = wmi.WMI()
        for process in c.Win32_Process(["ProcessID"], ParentProcessID=proc.pid):
            child_pid = process.ProcessID
        PROCESS_TERMINATE = 1
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE,
                                                    False,
                                                    child_pid)
        ctypes.windll.kernel32.TerminateProcess(handle, -1)
        ctypes.windll.kernel32.CloseHandle(handle)
        conf_text = file(os.path.join(os.path.dirname(binary),
                                      'bootstrap.ini'),
                         'rb').read()
        conf_text = conf_text.replace(('UserInstallation='
                                       '$SYSUSERCONFIG/OpenOffice.org/3'),
                                      ('UserInstallation='
                                       '{}/.openoffice.org/3').format(
                                              drive_letter))
        conf_file = file(os.path.join(os.path.dirname(binary),
                                      'bootstrap.ini'), 'wb')
        conf_file.write(conf_text)
        conf_file.close()

    @staticmethod
    def add_user_to_group(name, group="Users"):
        user_group_info = dict(domainandname=name)
        NetLocalGroupAddMembers(None, group, 3, [user_group_info])

    def create_run_once(self, filename):
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows"
                                   r"\CurrentVersion\RunOnce"),
                                  "",
                                  filename,
                                  win32con.REG_SZ)

    def set_auto_logon(self, username, password):
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "DefaultUserName",
                                  username,
                                  win32con.REG_SZ)
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "DefaultPassword",
                                  password,
                                  win32con.REG_SZ)
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "AutoAdminLogon",
                                  "1",
                                  win32con.REG_SZ)

    def remove_auto_logon(self, username):
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "DefaultUserName",
                                  username,
                                  win32con.REG_SZ)
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "DefaultPassword",
                                  "",
                                  win32con.REG_SZ)
        self.write_registry_value(win32con.HKEY_LOCAL_MACHINE,
                                  (r"SOFTWARE\Microsoft\Windows NT"
                                   r"\CurrentVersion\Winlogon"),
                                  "AutoAdminLogon",
                                  "0",
                                  win32con.REG_SZ)

    @staticmethod
    def redirect_special_folder(folder, drive):
        base_path = (r'Software\Microsoft\Windows'
                     r'\CurrentVersion\Explorer\User Shell Folders')
        destination = 'Documents' if folder == 'Personal' else folder
        try:
            reg_key = OpenKey(HKEY_CURRENT_USER, base_path, 0, KEY_ALL_ACCESS)
            SetValueEx(reg_key,
                       folder,
                       0,
                       REG_SZ,
                       os.path.join(drive, os.sep, destination))
            CloseKey(reg_key)
        except WindowsError:
            print "Problem redirecting folders."
            return False

    def write_registry_value(self,
                             hive_key,
                             key,
                             name,
                             data,
                             type_id=win32con.REG_SZ):
        try:
            key_handle = self.open_registry_key(hive_key, key)
            win32api.RegSetValueEx(key_handle, name, 0, type_id, data)
            win32api.RegCloseKey(key_handle)
        except Exception, e:
            print "writeRegistryValue failed:", hive_key, name, e

    @staticmethod
    def open_registry_key(hive_key, key):
        key_handle = None
        try:
            cur_key = ""
            for sub_key in key.split('\\'):
                if cur_key:
                    cur_key = cur_key + "\\" + sub_key
                else:
                    cur_key = sub_key
                key_handle = win32api.RegCreateKey(hive_key, cur_key)
        except Exception, e:
            key_handle = None
            print "open_registry_key failed:", hive_key, key, e
        return key_handle

    @staticmethod
    def delete_user_from_group(name, group="Administrators"):
        NetLocalGroupDelMembers(None, group, [name, ])

    @staticmethod
    def get_available_drive():
        drives = ['{}:'.format(letter) for letter in map(chr, range(67, 91))]
        win = wmi.WMI()
        for disk in win.Win32_LogicalDisk(DriveType=3):
            if disk.Caption:
                drives.remove(disk.Caption)
        for disk in win.Win32_LogicalDisk(DriveType=4):
            if disk.Caption:
                drives.remove(disk.Caption)
        for disk in win.Win32_LogicalDisk(DriveType=5):
            if disk.Caption:
                drives.remove(disk.Caption)
        return drives.pop()

    @staticmethod
    def map_network_drive(path,
                          drive_letter="X:",
                          username=None,
                          password=None,
                          persistent=False):
        flag = 'win32netcon.CONNECT_UPDATE_PROFILE' if persistent else 0
        win32wnet.WNetAddConnection2(DISK,
                                     drive_letter,
                                     path,
                                     None,
                                     username,
                                     password,
                                     flag)

    @staticmethod
    def unmap_network_drive(drive_letter="X:"):
        try:
            win32wnet.WNetCancelConnection2(drive_letter, 1, 0)
        except Exception:  # noqa
            print 'Error unmapping drive {}'.format(drive_letter)
            return False

    @staticmethod
    def hide_drive_letter(drive):
        base_path = (r'Software\Microsoft\Windows'
                     r'\CurrentVersion\Policies\Explorer')
        drives = {'A:': '1',
                  'B:': '2',
                  'C:': '4',
                  'D:': '8',
                  'E:': '16',
                  'F:': '32',
                  'G:': '64',
                  'H:': '128',
                  'I:': '256',
                  'J:': '512',
                  'K:': '1024',
                  'L:': '2048',
                  'M:': '4096',
                  'N:': '8192',
                  'O:': '16384',
                  'P:': '32768',
                  'Q:': '65536',
                  'R:': '131072',
                  'S:': '262144',
                  'T:': '524288',
                  'U:': '1048576',
                  'V:': '2097152',
                  'W:': '4194304',
                  'X:': '8388608',
                  'Y:': '16777216',
                  'Z:': '33554432'}
        try:
            reg_key = OpenKey(HKEY_CURRENT_USER, base_path, 0, KEY_ALL_ACCESS)
            SetValueEx(reg_key, 'NoDrives', 0, REG_DWORD, int(drives[drive]))
            CloseKey(reg_key)
        except WindowsError:
            print "Problem hiding Drive {}".format(drive)
            return False

    @staticmethod
    def set_env_variable(var_name, value, user=False):
        if user:
            path = r'Environment'
            reg = ConnectRegistry(None, HKEY_CURRENT_USER)
        else:
            path = (r'SYSTEM\CurrentControlSet'
                    r'\Control\Session Manager\Environment')
            reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        key = OpenKey(reg, path, 0, KEY_ALL_ACCESS)
        SetValueEx(key, var_name, 0, REG_EXPAND_SZ, value)
        win32gui.SendMessage(win32con.HWND_BROADCAST,
                             win32con.WM_SETTINGCHANGE, 0, 'Environment')

    @staticmethod
    def get_env_variable(var_name, default=''):
        key = default
        try:
            rkey = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                       (r'SYSTEM\CurrentControlSet\Control'
                                        r'\Session Manager\Environment'))
            try:
                key = str(win32api.RegQueryValueEx(rkey, var_name)[0])
                key = win32api.ExpandEnvironmentStrings(key)
            except Exception:  # noqa
                pass
        finally:
            win32api.RegCloseKey(rkey)
        return key

    @staticmethod
    def __adjust_privilege(priv, enable=True):
        # get the process token
        flags = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                                flags)
        id = win32security.LookupPrivilegeValue(None, priv)
        new_privileges = [(id, SE_PRIVILEGE_ENABLED)] if enable else [(id, 0)]
        win32security.AdjustTokenPrivileges(htoken, 0, new_privileges)

    def reboot(self,
               message="Workstation Rebooting",
               timeout=90,
               b_force=0,
               b_reboot=1):
        self.__adjust_privilege(SE_SHUTDOWN_NAME)
        try:
            win32api.InitiateSystemShutdown(None,
                                            message,
                                            timeout,
                                            b_force,
                                            b_reboot)
        finally:
            self.__adjust_privilege(SE_SHUTDOWN_NAME, 0)

    @staticmethod
    def create_next_file(path,
                         filename,
                         username,
                         password,
                         email,
                         fax_host_name,
                         admin_username,
                         admin_password):
        next_text = """from windowsxpsetup import *
import win32api
import time

if __name__=='__main__':
    servername = "VBOXSVR"
    time.sleep(20)
    comp=WindowsXp()
    comp.fax_setup('{username}', '{password}', '{email}', '{fax_host_name}')
    comp.map_network_drive(r"\\\\VBOXSVR\\WinMachine","X:")
    comp.set_env_variable('HOME', 'X:', user=True)
    comp.redirect_special_folder('Desktop', 'X:')
    comp.redirect_special_folder('Personal','X:')
    comp.hide_drive_lLetter('X:')
    comp.set_mozilla_profile('firefox', 'X:')
    comp.set_mozilla_profile('thunderbird', 'X:')
    comp.set_ooo_profile('X:')
    comp.set_administrator_account('{admin_username}','{admin_password}')
    comp.delete_user_from_group(win32api.GetUserName(),"Administrators")
    comp.remove_auto_logon(win32api.GetUserName())
    comp.reboot()""".format(username=username,
                            password=password,
                            email=email,
                            fax_host_name=fax_host_name,
                            admin_username=admin_username,
                            admin_password=admin_password)

        next_file = file(os.path.join(path, filename), "w")
        next_file.write(next_text)
        next_file.close()
