#!/usr/bin/env python3
import os, re, subprocess, platform
from utils.logger import setup_logger

class ConfigScanner:
    def __init__(self):
        self.logger = setup_logger("ConfigScanner")
        self.issues = []

    def scan(self):
        return {
            'ssh_config': self.check_ssh_config(),
            'firewall_status': self.check_firewall_status(),
            'sudo_config': self.check_sudo_config(),
            'network_services': self.check_network_services(),
            'issues': self.issues
        }

    def check_ssh_config(self):
        config_path = "/etc/ssh/sshd_config"
        issues = []
        if os.path.exists(config_path):
            content = open(config_path).read()
            if re.search(r'^PermitRootLogin\s+yes', content, re.MULTILINE):
                issues.append("SSH root login enabled")
                self.issues.append("SSH root login enabled")
            if re.search(r'^PasswordAuthentication\s+yes', content, re.MULTILINE):
                issues.append("SSH password authentication enabled")
                self.issues.append("SSH password authentication enabled")
        return {'issues': issues}

    def check_firewall_status(self):
        status = subprocess.getoutput('ufw status')
        if "inactive" in status.lower():
            self.issues.append("Firewall disabled")
            return {'status': 'inactive'}
        return {'status': 'active'}

    def check_sudo_config(self):
        output = subprocess.getoutput('grep -E "^(sudo|wheel)" /etc/group')
        return {'sudo_users': output.split("\n")}

    def check_network_services(self):
        system = platform.system().lower()
        if system.startswith('win'):
            cmd = 'netstat -ano'
            output = subprocess.getoutput(cmd)
            listening = [line for line in output.splitlines() if 'LISTENING' in line]
        else:
            cmd = 'netstat -tlnp'
            output = subprocess.getoutput(cmd)
            listening = [line for line in output.splitlines() if 'LISTEN' in line]
        return {
            'listening_ports': listening
        }

