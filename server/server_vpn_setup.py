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

# --- USER CONFIGURATION ---
# PLEASE REPLACE THIS WITH YOUR SERVER'S PUBLIC IP ADDRESS
SERVER_PUBLIC_IP = "YOUR_IP_HERE"
# --- END USER CONFIGURATION ---

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
    # 1. Check if IP address is set
    if SERVER_PUBLIC_IP == "YOUR_IP_HERE":
        logging.error("Please edit the script and set the SERVER_PUBLIC_IP variable.")
        sys.exit(1)

    # 2. Check for sudo
    check_sudo()

    # 3. Check for Linux
    if platform.system() != "Linux":
        logging.error("This script is designed for Linux (Debian-based).")
        sys.exit(1)

    logging.info("SANYA-VPN OpenVPN Server Setup -- STARTING")
    install_openvpn()
    setup_easyrsa()
    create_server_config()

    # Create the default user
    create_vpn_user("SANYAPI", "l1galv9n")

    # Generate the client .ovpn file
    generate_client_config(SERVER_PUBLIC_IP)

    logging.info("SANYA-VPN OpenVPN Server Setup -- COMPLETE")
    logging.info("Default user 'SANYAPI' has been created.")

def install_openvpn():
    """Installs OpenVPN, Easy-RSA, and the PAM authentication plugin."""
    logging.info("Installing OpenVPN and Easy-RSA...")
    try:
        run_command(['apt-get', 'update'], check=True)
        # On Debian Bookworm and newer, the auth-pam plugin is included in the 'openvpn' package itself
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
plugin /usr/lib/openvpn/openvpn-auth-pam.so login
client-cert-not-required
username-as-common-name
"""
    try:
        with open("/etc/openvpn/server.conf", "w") as f:
            f.write(config_content)
        logging.info("OpenVPN server.conf created.")
    except IOError as e:
        logging.error(f"Failed to write server configuration: {e}")
        sys.exit(1)

def create_vpn_user(username, password):
    """Creates a new system user for VPN access, without a home directory."""
    logging.info(f"Creating VPN user: {username}...")
    try:
        # --no-create-home: Don't create a home directory
        # --shell /usr/sbin/nologin: Prevent shell access
        run_command(['useradd', username, '--no-create-home', '--shell', '/usr/sbin/nologin'], check=True)
        # Set the password for the new user
        proc = subprocess.Popen(['passwd', username], stdin=subprocess.PIPE)
        proc.stdin.write(f"{password}\n{password}\n".encode('utf-8'))
        proc.stdin.close()
        proc.wait()
        logging.info(f"Successfully created user '{username}'.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to create user '{username}': {e}")
        sys.exit(1)

def generate_client_config(server_ip):
    """Generates a .ovpn file for the client."""
    logging.info("Generating client configuration file (SANYA-VPN.ovpn)...")
    ca_path = "/etc/openvpn/keys/ca.crt"
    try:
        with open(ca_path, 'r') as f:
            ca_content = f.read()

        client_config = f"""
client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
auth-user-pass

<ca>
{ca_content}
</ca>
"""
        # Find the home directory of the user who invoked sudo
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user:
            output_path = f"/home/{sudo_user}/SANYA-VPN.ovpn"
        else:
            # Fallback to current directory if SUDO_USER is not set
            output_path = "SANYA-VPN.ovpn"

        with open(output_path, 'w') as f:
            f.write(client_config)

        # Set correct ownership for the file
        if sudo_user:
            run_command(['chown', f'{sudo_user}:{sudo_user}', output_path], check=True)

        logging.info(f"Client configuration saved to: {output_path}")
        logging.info("Please transfer this file to your client machine.")

    except (IOError, FileNotFoundError) as e:
        logging.error(f"Failed to generate client config: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
