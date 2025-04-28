import re
import ipaddress
import subprocess
import shlex # Import shlex

def validate_ip_address(ip_address_string):
    """
    Validates if a given string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_address_string)
        return True
    except ValueError:
        return False

def validate_port(port):
    """
    Validates if a given port number is within the valid range (1-65535).
    """
    return 1 <= port <= 65535

def validate_protocol(protocol):
    """
    Validates if a given protocol is a valid Snort protocol.
    """
    valid_protocols = ["tcp", "udp", "icmp", "ip", "http", "ftp", "smtp", "dns"]
    return protocol.lower() in valid_protocols

def validate_action(action):
    """
    Validates if a given action is a valid Snort action.
    """
    valid_actions = ["alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"]
    return action.lower() in valid_actions

def validate_direction(direction):
    """
    Validates the direction operator.
    """
    valid_directions = ["->", "<-", "<>"]
    return direction in valid_directions

def escape_content(content):
    """
    Escapes special characters in the content string for Snort rules.
    """
    escaped_content = content.replace("|", "||").replace(";", "\\;")
    escaped_content = re.sub(r"[\x00-\x1f\x7f]", lambda m: f"|{ord(m.group(0)):02x}|", escaped_content)
    return escaped_content

def generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, options=None):
    """
    Generates a Snort rule string based on the provided parameters.
    """
    if not validate_action(action):
        print(f"Error: Invalid action '{action}'.")
        return ""
    if not validate_protocol(protocol):
        print(f"Error: Invalid protocol '{protocol}'.")
        return ""
    if not validate_direction(direction):
        print(f"Error: Invalid direction '{direction}'.")
        return ""
    if not (src_ip == "any" or validate_ip_address(src_ip) or "/" in src_ip or src_ip.startswith("!")):
        print(f"Error: Invalid source IP address '{src_ip}'.")
        return ""
    if not (dest_ip == "any" or validate_ip_address(dest_ip) or "/" in dest_ip or dest_ip.startswith("!")):
        print(f"Error: Invalid destination IP address '{dest_ip}'.")
        return ""
    if not (src_port == "any" or ":" in src_port or validate_port(int(src_port)) if src_port.isdigit() else True):
        print(f"Error: Invalid source port '{src_port}'.")
        return ""
    if not (dest_port == "any" or ":" in dest_port or validate_port(int(dest_port)) if dest_port.isdigit() else True):
        print(f"Error: Invalid destination port '{dest_port}'.")
        return ""
    rule = f"{action} {protocol} {src_ip} {src_port} {direction} {dest_ip} {dest_port} "
    if options:
        rule += "("
        option_strings = []
        for key, value in options.items():
            if key == "content":
                value = f'"{escape_content(value)}"'
            elif key in ["offset", "depth", "within", "distance", "count"]: # Added count
                try:
                    int(value)
                except ValueError:
                    print(f"Error: The value for '{key}' must be an integer.  Value provided: '{value}'")
                    return ""
            elif key in ["http_uri", "http_header", "uri", "header"]: # Added uri and header
                 value = f'"{escape_content(value)}"'
            elif key == "rawbytes":
                if value not in ["", " "]:
                    print(f"Error: The value for '{key}' must be empty. Value provided: '{value}'")
                    return ""
            elif key in ["flags", "icode", "itype", "ttl", "tos"]:
                value = value.lower()
            elif key == "dsize":
                if not (value.startswith(">") or value.startswith("<") or value.isdigit()):
                    print(f"Error: Invalid dsize format.  Must be >, <, or an integer. Value: {value}")
                    return ""
            elif key == "reference":
                if not re.match(r"(\w+,\w+,\S+)", value):
                    print(f"Error: Invalid reference format.  Must be: <type>,<name>,<url> Value: {value}")
                    return ""
            option_strings.append(f"{key}:{value};")
        rule += " ".join(option_strings)
        rule += ")"
    return rule

def run_pentbox_honeypot(ip_address, port):
    """
    Runs a Pentbox honeypot on the specified IP address and port.

    Args:
        ip_address (str): The IP address to run the honeypot on.
        port (int): The port number to run the honeypot on.

    Returns:
        subprocess.Popen: The process object of the running honeypot.  None on error.
    """
    try:
        # Construct the command to start the Pentbox honeypot.
        #  This assumes that 'pentbox' is in the system's PATH.  You might need to
        #  adjust the command depending on how Pentbox is installed.
        command = ["pentbox", "run", "Honeypot", "-i", ip_address, "-p", str(port)]
        print(f"Starting Pentbox honeypot: {command}")

        # Start the honeypot in a new process.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Honeypot is running on {ip_address}:{port}...")
        return process

    except FileNotFoundError:
        print("Error: Pentbox is not installed or not in your system's PATH.")
        print("Please make sure Pentbox is installed and accessible from the command line.")
        return None
    except Exception as e:
        print(f"An error occurred while starting the honeypot: {e}")
        return None

def main():
    """
    Main function to demonstrate the usage of the generate_snort_rule function
    and integrate with Pentbox honeypot.
    """
    # Honeypot configuration
    honeypot_ip = "192.168.100.5"  #  Change this to your desired honeypot IP
    honeypot_port = 8080             #  Change this to your desired honeypot port

    # Snort rule configuration
    action = "alert"
    protocol = "tcp"
    src_ip = "any"  # Monitor traffic from any source
    src_port = "any"
    direction = "->"
    dest_ip = honeypot_ip  # Destination IP is the honeypot IP
    dest_port = str(honeypot_port)
    options = {
        "msg": "Possible Honeypot Interaction!",
        "flow": "to_server,established",
        "content": "GET /",
        "http_uri": "/",
        "depth": 10,
        "offset": 0,
        "within": 20,
        "distance": 5,
        "count": 1,
        "http_header": "User-Agent: BadBot",
        "rawbytes": "",
        "flags": "S",  # Check for SYN flag
        "icode": 0,
        "itype": 8,
        "ttl": ">10",
        "tos": "0",
        "dsize": ">100",
        "reference": "url,example,www.example.com",
        "header": "Host: test.com",
        "uri": "/test.php"
    }

    # 1. Generate the Snort rule
    rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, options)
    if rule:
        print("Generated Snort Rule:")
        print(rule)
        print("\nTo use this rule, add it to your Snort configuration file (e.g., local.rules).")

        # 2. Run the Pentbox honeypot
        honeypot_process = run_pentbox_honeypot(honeypot_ip, honeypot_port)
        if honeypot_process:
            print("\nHoneypot is running.  Snort should now detect traffic to it.")
            print("Press Ctrl+C to stop the honeypot.")
            try:
                # Keep the script running so the honeypot stays active.
                #  The honeypot process runs in the background.
                while True:
                    pass
            except KeyboardInterrupt:
                print("\nStopping Pentbox honeypot...")
                # Cleanly terminate the honeypot process.
                honeypot_process.terminate()
                honeypot_process.wait()
                print("Honeypot stopped.")
        else:
            print("Honeypot could not be started.  Please check the error messages.")
    else:
        print("Failed to generate Snort rule.  Please check the errors above.")
