#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN OpenVPN Server Setup Script

This script automates the setup of an OpenVPN server on a Debian-based system,
such as Raspberry Pi OS. It handles the installation of OpenVPN, configuration,
and user management.
"""

import subprocess
import os
import sys
import logging
import platform
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def run_command(command, check=True):
    """
    Executes a shell command and logs its output.
    """
    logging.info(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            encoding='utf-8'
        )
        if result.stdout:
            logging.info(f"Output:\n{result.stdout.strip()}")
        if result.stderr:
            logging.warning(f"Errors/Warnings:\n{result.stderr.strip()}")
        return result
    except FileNotFoundError:
        logging.error(f"Command not found: {command[0]}")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}: {' '.join(command)}")
        logging.error(f"STDOUT: {e.stdout.strip()}")
        logging.error(f"STDERR: {e.stderr.strip()}")
        raise

def check_sudo():
    """
    Checks if the script is being run with superuser (sudo) privileges.
    """
    if os.geteuid() != 0:
        logging.error("This script must be run as root. Please use 'sudo'.")
        sys.exit(1)
    logging.info("Sudo privileges check passed.")

def main():
    """
    Main function to orchestrate the server setup process.
    """
    logging.info("SANYA-VPN OpenVPN Server Setup -- STARTING")

    # 1. Check for sudo
    check_sudo()

    # 2. Check for Linux
    if platform.system() != "Linux":
        logging.error("This script is designed for Linux (Debian-based).")
        sys.exit(1)

    install_openvpn()
    setup_easyrsa()
    create_server_config()

    logging.info("SANYA-VPN OpenVPN Server Setup -- COMPLETE")

def install_openvpn():
    """Installs OpenVPN and Easy-RSA."""
    logging.info("Installing OpenVPN and Easy-RSA...")
    try:
        run_command(['apt-get', 'update'], check=True)
        run_command(['apt-get', 'install', '-y', 'openvpn', 'easy-rsa'], check=True)
        logging.info("OpenVPN and Easy-RSA installed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to install packages: {e}")
        sys.exit(1)

def setup_easyrsa():
    """Sets up Easy-RSA and generates the necessary certificates and keys."""
    logging.info("Setting up Easy-RSA and generating certificates...")
    easyrsa_dir = '/etc/openvpn/easy-rsa'
    try:
        # Create the Easy-RSA directory
        run_command(['make-cadir', easyrsa_dir], check=True)

        # WARNING: This is a simplified, non-interactive setup.
        # In a real-world scenario, these values should be configured.
        os.chdir(easyrsa_dir)
        run_command(['./easyrsa', 'init-pki'], check=True)
        run_command(['./easyrsa', '--batch', 'build-ca', 'nopass'], check=True)
        run_command(['./easyrsa', '--batch', 'gen-req', 'server', 'nopass'], check=True)
        run_command(['./easyrsa', '--batch', 'sign-req', 'server', 'server'], check=True)
        run_command(['./easyrsa', 'gen-dh'], check=True)

        # Copy generated files to the keys directory
        keys_dir = os.path.join(easyrsa_dir, 'pki')
        openvpn_keys_dir = '/etc/openvpn/keys'
        if not os.path.exists(openvpn_keys_dir):
            os.makedirs(openvpn_keys_dir)

        files_to_copy = {
            'ca.crt': os.path.join(keys_dir, 'ca.crt'),
            'server.crt': os.path.join(keys_dir, 'issued', 'server.crt'),
            'server.key': os.path.join(keys_dir, 'private', 'server.key'),
            'dh.pem': os.path.join(keys_dir, 'dh.pem')
        }

        for dest, src in files_to_copy.items():
            run_command(['cp', src, os.path.join(openvpn_keys_dir, dest)], check=True)

        logging.info("Easy-RSA setup and certificate generation complete.")

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed during Easy-RSA setup: {e}")
        sys.exit(1)

def create_server_config():
    """Creates a basic OpenVPN server configuration file."""
    logging.info("Creating OpenVPN server configuration...")
    config_content = """
port 1194
proto udp
dev tun
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/server.crt
key /etc/openvpn/keys/server.key
dh /etc/openvpn/keys/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
"""
    try:
        with open("/etc/openvpn/server.conf", "w") as f:
            f.write(config_content)
        logging.info("OpenVPN server.conf created.")
    except IOError as e:
        logging.error(f"Failed to write server configuration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
