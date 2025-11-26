#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SANYA-VPN OpenVPN Server Setup Script.

This script automates the setup of an OpenVPN server on a Debian-based system,
such as Raspberry Pi OS. It handles the installation of OpenVPN, Easy-RSA,
server configuration, user management, and client configuration generation.

Execution requires superuser (sudo) privileges.
"""

import subprocess
import os
import sys
import logging
import platform
import pwd
import shutil
import getpass

# --- USER CONFIGURATION ---
# PLEASE REPLACE THIS WITH YOUR SERVER'S PUBLIC IP ADDRESS
SERVER_PUBLIC_IP = "YOUR_IP_HERE"
# Default VPN user to be created
DEFAULT_VPN_USER = "SANYAPI"
# OpenVPN configuration
VPN_PORT = 1194
VPN_PROTOCOL = "udp"
VPN_NETWORK = "10.8.0.0"
VPN_NETMASK = "255.255.255.0"
# --- END USER CONFIGURATION ---

# Configure logging to output to standard output.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)


def run_command(command, check=True, capture_output=True, working_dir=None):
    """Executes a shell command and logs its output.

    Args:
        command (list): The command to execute, as a list of strings.
        check (bool): If True, raises a CalledProcessError if the command
                      returns a non-zero exit code.
        capture_output (bool): If True, captures stdout and stderr.
        working_dir (str, optional): The directory to run the command in.

    Returns:
        subprocess.CompletedProcess: The result of the command execution.

    Raises:
        FileNotFoundError: If the command executable is not found.
        subprocess.CalledProcessError: If the command fails and `check` is True.
    """
    logging.info(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            check=check,
            encoding='utf-8',
            cwd=working_dir
        )
        if capture_output:
            if result.stdout:
                logging.debug(f"Output:\n{result.stdout.strip()}")
            if result.stderr:
                logging.debug(f"Errors/Warnings:\n{result.stderr.strip()}")
        return result
    except FileNotFoundError:
        logging.error(f"Command not found: {command[0]}. Is it in the system's PATH?")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(
            f"Command failed with exit code {e.returncode}: "
            f"{' '.join(command)}"
        )
        if capture_output:
            logging.error(f"STDOUT: {e.stdout.strip()}")
            logging.error(f"STDERR: {e.stderr.strip()}")
        raise


def check_sudo():
    """Checks if the script is being run with superuser privileges.

    Exits the script with an error if not run as root.
    """
    if os.geteuid() != 0:
        logging.error("This script must be run as root. Please use 'sudo'.")
        sys.exit(1)
    logging.info("Sudo privileges check passed.")


def is_debian_based():
    """Checks if the operating system is Debian-based."""
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('ID_LIKE='):
                    if 'debian' in line:
                        return True
    except FileNotFoundError:
        return False
    return False


def install_openvpn():
    """Installs OpenVPN and Easy-RSA using the system's package manager.

    Handles updating the package list and installing the required packages.
    Exits the script if the installation fails.
    """
    logging.info("Updating package lists and installing OpenVPN and Easy-RSA...")
    try:
        run_command(['apt-get', 'update'], check=True)
        # On Debian Bookworm and newer, the auth-pam plugin is included
        # in the 'openvpn' package itself.
        run_command(
            ['apt-get', 'install', '-y', 'openvpn', 'easy-rsa'],
            check=True
        )
        logging.info("OpenVPN and Easy-RSA installed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to install packages: {e}")
        logging.error("Please ensure you are on a Debian-based system and have an active internet connection.")
        sys.exit(1)


def setup_easyrsa():
    """Sets up Easy-RSA and generates server certificates and keys.

    This function performs the following steps:
    1. Removes any existing Easy-RSA directory for a clean setup.
    2. Creates a new Easy-RSA Certificate Authority (CA).
    3. Builds the CA, a server request, and signs the server request.
    4. Generates Diffie-Hellman parameters.
    5. Copies all necessary generated files to /etc/openvpn/keys.

    Exits the script if any step fails.
    """
    logging.info("Setting up Easy-RSA and generating certificates...")
    easyrsa_dir = '/etc/openvpn/easy-rsa'
    openvpn_keys_dir = '/etc/openvpn/keys'

    try:
        # Clean up any previous attempts to ensure a fresh start.
        if os.path.exists(easyrsa_dir):
            logging.warning(
                f"Removing existing directory to ensure a clean setup: {easyrsa_dir}"
            )
            shutil.rmtree(easyrsa_dir)

        if os.path.exists(openvpn_keys_dir):
            logging.warning(
                f"Removing existing directory to ensure a clean setup: {openvpn_keys_dir}"
            )
            shutil.rmtree(openvpn_keys_dir)

        # Create the Easy-RSA directory and initialize the PKI
        shutil.copytree('/usr/share/easy-rsa', easyrsa_dir)
        run_command(['./easyrsa', 'init-pki'], check=True, working_dir=easyrsa_dir)

        # Generate certificates and keys.
        run_command(['./easyrsa', '--batch', 'build-ca', 'nopass'], check=True, working_dir=easyrsa_dir)
        run_command(
            ['./easyrsa', '--batch', 'gen-req', 'server', 'nopass'],
            check=True, working_dir=easyrsa_dir
        )
        run_command(
            ['./easyrsa', '--batch', 'sign-req', 'server', 'server'],
            check=True, working_dir=easyrsa_dir
        )
        run_command(['./easyrsa', 'gen-dh'], check=True, working_dir=easyrsa_dir)

        # Copy generated files to the final keys directory.
        os.makedirs(openvpn_keys_dir, exist_ok=True)
        pki_dir = os.path.join(easyrsa_dir, 'pki')

        files_to_copy = {
            'ca.crt': os.path.join(pki_dir, 'ca.crt'),
            'server.crt': os.path.join(pki_dir, 'issued', 'server.crt'),
            'server.key': os.path.join(pki_dir, 'private', 'server.key'),
            'dh.pem': os.path.join(pki_dir, 'dh.pem')
        }

        for dest, src in files_to_copy.items():
            shutil.copy(src, os.path.join(openvpn_keys_dir, dest))

        logging.info("Easy-RSA setup and certificate generation complete.")

    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        logging.error(f"Failed during Easy-RSA setup: {e}")
        sys.exit(1)


def create_server_config():
    """Creates the OpenVPN server configuration file.

    Writes the `server.conf` file to `/etc/openvpn/` with settings for
    port, protocol, certificates, IP range, and user authentication via PAM.

    Exits the script if the configuration file cannot be written.
    """
    logging.info("Creating OpenVPN server configuration...")
    config_content = f"""
port {VPN_PORT}
proto {VPN_PROTOCOL}
dev tun
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/server.crt
key /etc/openvpn/keys/server.key
dh /etc/openvpn/keys/dh.pem
server {VPN_NETWORK} {VPN_NETMASK}
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
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
plugin /usr/lib/openvpn/openvpn-auth-pam.so login
client-cert-not-required
username-as-common-name
"""
    try:
        os.makedirs("/var/log/openvpn", exist_ok=True)
        with open("/etc/openvpn/server.conf", "w") as f:
            f.write(config_content)
        logging.info("OpenVPN server.conf created successfully.")
    except IOError as e:
        logging.error(f"Failed to write server configuration: {e}")
        sys.exit(1)


def create_vpn_user(username, password):
    """Creates a new system user for VPN access without a home directory.

    This user is created with a non-interactive shell (`/usr/sbin/nologin`)
    to prevent direct system login. Checks if user already exists.

    Args:
        username (str): The username for the new VPN user.
        password (str): The password for the user.

    Exits the script if user creation fails.
    """
    try:
        pwd.getpwnam(username)
        logging.warning(f"User '{username}' already exists. Skipping creation.")
        return
    except KeyError:
        logging.info(f"Creating VPN user: {username}...")

    try:
        # --no-create-home: Don't create a home directory.
        # --shell /usr/sbin/nologin: Prevent shell access.
        run_command(
            ['useradd', username, '--no-create-home', '--shell',
             '/usr/sbin/nologin'],
            check=True
        )
        # Set the password for the new user non-interactively.
        proc = subprocess.Popen(['passwd', username], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(f"{password}\n{password}\n".encode('utf-8'))

        if proc.returncode != 0:
            logging.error(f"Failed to set password for '{username}'.")
            logging.error(f"passwd stderr: {stderr.decode('utf-8').strip()}")
            sys.exit(1)

        logging.info(f"Successfully created user '{username}'.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to create user '{username}': {e}")
        sys.exit(1)

def get_vpn_password():
    """Prompts the user to enter and verify a password for the VPN user."""
    while True:
        try:
            password = getpass.getpass(
                f"Enter a password for the VPN user '{DEFAULT_VPN_USER}': "
            )
            if not password:
                print("Password cannot be empty. Please try again.")
                continue

            password_verify = getpass.getpass("Verify password: ")
            if password == password_verify:
                return password
            else:
                print("Passwords do not match. Please try again.")
        except KeyboardInterrupt:
            print("\nSetup cancelled by user.")
            sys.exit(1)


def generate_client_config(server_ip):
    """Generates a .ovpn file for the client.

    The generated file includes the server IP, port, and the CA certificate
    embedded within it. It is saved to the home directory of the user who
    ran the script with `sudo`.

    Args:
        server_ip (str): The public IP address of the OpenVPN server.

    Exits the script if the configuration file cannot be generated.
    """
    client_config_name = "SANYA-VPN.ovpn"
    logging.info(f"Generating client configuration file ({client_config_name})...")
    ca_path = "/etc/openvpn/keys/ca.crt"
    try:
        with open(ca_path, 'r') as f:
            ca_content = f.read()

        client_config = f"""
client
dev tun
proto {VPN_PROTOCOL}
remote {server_ip} {VPN_PORT}
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
        # Find the home directory of the user who invoked sudo.
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user:
            # Correctly get the home directory for any user, including root.
            user_home = pwd.getpwnam(sudo_user).pw_dir
            output_path = os.path.join(user_home, client_config_name)
        else:
            # Fallback to current dir if SUDO_USER is not set (direct root).
            output_path = client_config_name

        with open(output_path, 'w') as f:
            f.write(client_config)

        # Set correct ownership for the file.
        if sudo_user:
            uid = pwd.getpwnam(sudo_user).pw_uid
            gid = pwd.getpwnam(sudo_user).pw_gid
            os.chown(output_path, uid, gid)

        logging.info(f"Client configuration saved to: {output_path}")
        logging.info("Please transfer this file to your client machine.")

    except (IOError, FileNotFoundError) as e:
        logging.error(f"Failed to generate client config: {e}")
        sys.exit(1)


def main():
    """Main function to orchestrate the OpenVPN server setup process."""
    # 1. Check if the server's public IP address has been set.
    if SERVER_PUBLIC_IP == "YOUR_IP_HERE":
        logging.error(
            "Configuration error: Please edit the script and set the "
            "SERVER_PUBLIC_IP variable."
        )
        sys.exit(1)

    # 2. Ensure the script is run with sudo privileges.
    check_sudo()

    # 3. Verify that the operating system is Linux and Debian-based.
    if platform.system() != "Linux" or not is_debian_based():
        logging.error(
            "This script is designed for Debian-based Linux systems only."
        )
        sys.exit(1)

    logging.info("SANYA-VPN OpenVPN Server Setup -- STARTING")

    install_openvpn()
    setup_easyrsa()
    create_server_config()

    # Get a secure password for the default user
    vpn_password = get_vpn_password()

    # Create the default user.
    create_vpn_user(DEFAULT_VPN_USER, vpn_password)

    # Generate the client .ovpn file for easy connection.
    generate_client_config(SERVER_PUBLIC_IP)

    # Enable and start the OpenVPN service
    logging.info("Enabling and starting the OpenVPN service...")
    try:
        run_command(['systemctl', 'enable', 'openvpn@server'], check=True)
        run_command(['systemctl', 'start', 'openvpn@server'], check=True)
        logging.info("OpenVPN service has been started successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to start OpenVPN service: {e}")
        logging.error("You may need to start it manually: 'sudo systemctl start openvpn@server'")

    logging.info("SANYA-VPN OpenVPN Server Setup -- COMPLETE")
    logging.info(f"Default user '{DEFAULT_VPN_USER}' has been created.")
    logging.info("Server setup is finished. You can now use the generated .ovpn file.")


if __name__ == "__main__":
    main()
