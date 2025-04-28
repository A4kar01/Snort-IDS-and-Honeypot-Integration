import re
import ipaddress
import subprocess
import shlex
import time
import logging  # Import the logging module

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set the logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ip_address(ip_address_string):
    """
    Validates if a given string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_address_string)
        return True
    except ValueError:
        logging.error(f"Invalid IP address: {ip_address_string}")
        return False

def validate_port(port):
    """
    Validates if a given port number is within the valid range (1-65535).
    """
    if not 1 <= port <= 65535:
        logging.error(f"Invalid port: {port}")
        return False
    return True

def validate_protocol(protocol):
    """
    Validates if a given protocol is a valid Snort protocol.
    """
    valid_protocols = ["tcp", "udp", "icmp", "ip", "http", "ftp", "smtp", "dns", "ssh", "telnet", "nntp", "imap"]  # Added more protocols
    if protocol.lower() not in valid_protocols:
        logging.error(f"Invalid protocol: {protocol}")
        return False
    return True

def validate_action(action):
    """
    Validates if a given action is a valid Snort action.
    """
    valid_actions = ["alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop", "reactivate"] # Added reactivate
    if action.lower() not in valid_actions:
        logging.error(f"Invalid action: {action}")
        return False
    return True

def validate_direction(direction):
    """
    Validates the direction operator.
    """
    valid_directions = ["->", "<-", "<>"]
    if direction not in valid_directions:
        logging.error(f"Invalid direction: {direction}")
        return False
    return True

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
        return ""
    if not validate_protocol(protocol):
        return ""
    if not validate_direction(direction):
        return ""
    if not (src_ip == "any" or validate_ip_address(src_ip) or "/" in src_ip or src_ip.startswith("!")):
        return ""
    if not (dest_ip == "any" or validate_ip_address(dest_ip) or "/" in dest_ip or dest_ip.startswith("!")):
        return ""
    if not (src_port == "any" or ":" in src_port or validate_port(int(src_port)) if src_port.isdigit() else True):
        return ""
    if not (dest_port == "any" or ":" in dest_port or validate_port(int(dest_port)) if dest_port.isdigit() else True):
        return ""

    rule = f"{action} {protocol} {src_ip} {src_port} {direction} {dest_ip} {dest_port} "
    if options:
        rule += "("
        option_strings = []
        for key, value in options.items():
            if key == "content":
                value = f'"{escape_content(value)}"'
            elif key in ["offset", "depth", "within", "distance", "count", "to_ports", "fragbits", "ip_proto", "sameip", "replace"]: # Added more options
                try:
                    int(value)
                except ValueError:
                    logging.error(f"Error: The value for '{key}' must be an integer. Value provided: '{value}'")
                    return ""
            elif key in ["http_uri", "http_header", "uri", "header", "rawbytes", "msg", "logdata", "metadata"]: # Added msg, logdata, metadata
                 value = f'"{escape_content(value)}"'
            elif key in ["flags", "icode", "itype", "ttl", "tos", "fragsize", "id"]: # Added fragsize, id
                value = value.lower()
            elif key == "dsize":
                if not (value.startswith(">") or value.startswith("<") or value.isdigit()):
                    logging.error(f"Error: Invalid dsize format.  Must be >, <, or an integer. Value: {value}")
                    return ""
            elif key == "reference":
                if not re.match(r"(\w+,\w+,\S+)", value):
                    logging.error(f"Error: Invalid reference format.  Must be: <type>,<name>,<url> Value: {value}")
                    return ""
            elif key == "threshold":
                if not re.match(r"(type\s\w+,\strack\s\w+,\scount\s\d+)", value):
                    logging.error(f"Error: Invalid threshold format. Must be: type <type>, track <track>, count <count> Value: {value}")
                    return ""
            elif key == "session":
                if value not in ["all", "ip", "host"]:
                    logging.error(f"Error: Invalid session value.  Must be all, ip, or host. Value: {value}")
                    return ""
            elif key == "tag": #added tag
                if not re.match(r"(\w+,\s\d+)", value):
                    logging.error(f"Error: Invalid tag format. Must be: <string>, <number> Value: {value}")
                    return ""
            option_strings.append(f"{key}:{value};")
        rule += " ".join(option_strings)
        rule += ")"
    return rule

def run_pentbox_honeypot(ip_address, port, pentbox_path="pentbox", timeout=None):
    """
    Runs a Pentbox honeypot on the specified IP address and port.

    Args:
        ip_address (str): The IP address to run the honeypot on.
        port (int): The port number to run the honeypot on.
        pentbox_path (str, optional): The path to the Pentbox executable.
            Defaults to "pentbox", assuming it's in the system's PATH.
        timeout (int, optional):  Timeout in seconds to wait for the honeypot to start.
            If None, waits indefinitely.  Defaults to None.

    Returns:
        subprocess.Popen: The process object of the running honeypot.  None on error.
    """
    try:
        # Construct the command to start the Pentbox honeypot.
        command = [pentbox_path, "run", "Honeypot", "-i", ip_address, "-p", str(port)]
        logging.info(f"Starting Pentbox honeypot: {command}")

        # Use subprocess.Popen() to start the honeypot.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"Honeypot is running on {ip_address}:{port}...")
        if timeout:
            logging.info(f"Waiting for honeypot to start with timeout of {timeout} seconds.")
            start_time = time.time()
            while process.poll() is None and (time.time() - start_time) < timeout:
                time.sleep(1)
            if process.poll() is not None:
                logging.error("Honeypot process exited before timeout.")
                process.terminate()
                process.wait()
                return None
            elif (time.time() - start_time) >= timeout:
                logging.error("Honeypot start timed out.")
                process.terminate()
                process.wait()
                return None
        return process

    except FileNotFoundError:
        logging.error(f"Pentbox is not installed or not found at the specified path: {pentbox_path}.")
        logging.error("Please make sure Pentbox is installed and the path is correct.")
        return None
    except Exception as e:
        logging.error(f"An error occurred while starting the honeypot: {e}")
        return None

def stop_pentbox_honeypot(process):
    """
    Stops the Pentbox honeypot process.

    Args:
        process (subprocess.Popen): The process object of the running honeypot.
    """
    if process:
        logging.info("Stopping Pentbox honeypot...")
        process.terminate()
        return_code = process.wait()
        if return_code == 0:
            logging.info("Honeypot stopped successfully.")
        else:
            logging.error(f"Honeypot stopped with error code: {return_code}")
    else:
        logging.warning("No honeypot process to stop.")

def create_snort_config(rules, config_file="snort.conf", include_path="/usr/local/etc/snort/rules"):
    """
    Creates a basic Snort configuration file.

    Args:
        rules (list): A list of Snort rule strings.
        config_file (str, optional): The name of the Snort configuration file to create.
            Defaults to "snort.conf".
        include_path (str, optional):  The path where the rules are included.
    """
    try:
        with open(config_file, "w") as f:
            f.write("preprocessor http_inspect:\n")
            f.write("preprocessor frag3:\n")
            f.write("preprocessor stream5_tcp:\n")
            f.write("preprocessor stream5_udp:\n")
            f.write("var RULE_PATH {};\n".format(include_path))
            f.write("include $RULE_PATH/default.rules\n")
            f.write("include $RULE_PATH/local.rules\n") # Include a local.rules file
            f.write("\n")
            for rule in rules:
                f.write(f"{rule}\n")
        logging.info(f"Snort configuration file created: {config_file}")
    except Exception as e:
        logging.error(f"Error creating Snort configuration file: {e}")

def append_snort_rule(rule, rules_file="local.rules"):
    """
    Appends a Snort rule to an existing Snort rules file (e.g., local.rules).

    Args:
        rule (str): The Snort rule string to append.
        rules_file (str, optional): The name of the Snort rules file.
            Defaults to "local.rules".
    """
    try:
        with open(rules_file, "a") as f:
            f.write(f"{rule}\n")
        logging.info(f"Snort rule appended to {rules_file}: {rule}")
    except Exception as e:
        logging.error(f"Error appending Snort rule: {e}")

def list_snort_rules(rules_file="local.rules"):
    """
    Lists the Snort rules from a rules file.

    Args:
        rules_file (str, optional): The name of the Snort rules file.
            Defaults to "local.rules".
    """
    try:
        with open(rules_file, "r") as f:
            rules = f.readlines()
        if not rules:
            logging.info(f"No rules found in {rules_file}")
            return []
        else:
            logging.info(f"Rules found in {rules_file}:")
            for rule in rules:
                logging.info(rule.strip())
            return [rule.strip() for rule in rules]
    except FileNotFoundError:
        logging.error(f"Error: Rules file not found: {rules_file}")
        return []
    except Exception as e:
        logging.error(f"Error reading Snort rules: {e}")
        return []

def main():
    """
    Main function to demonstrate the usage of the generate_snort_rule function
    and integrate with Pentbox honeypot.
    """
    # Honeypot configuration
    honeypot_ip = "192.168.100.5"
    honeypot_port = 8080
    pentbox_path = "pentbox"  # Change this to the actual path if needed
    honeypot_timeout = 60  # Timeout in seconds

    # Snort rule configuration
    action = "alert"
    protocol = "tcp"
    src_ip = "any"
    src_port = "any"
    direction = "->"
    dest_ip = honeypot_ip
    dest_port = str(honeypot_port)
    options = {
        "msg": "Possible Honeypot Interaction: HTTP GET",
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
        "flags": "S",
        "icode": 0,
        "itype": 8,
        "ttl": ">10",
        "tos": "0",
        "dsize": ">100",
        "reference": "url,example,www.example.com",
        "header": "Host: test.com",
        "uri": "/test.php",
        "threshold": "type limit, track by_src, count 5",
        "session": "all",
        "tag": "hacker_activity, 12345", #added tag
        "to_ports": 80,
        "fragbits": 0,
        "ip_proto": 6,
        "sameip": 1,
        "replace": 200,
        "logdata": "time",
        "metadata": "policy balanced-security"
    }

    # 1. Generate the Snort rule
    rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, options)
    if rule:
        print("Generated Snort Rule:")
        print(rule)
        print("\nTo use this rule, add it to your Snort configuration file (e.g., local.rules).")

        # 2. Run the Pentbox honeypot
        honeypot_process = run_pentbox_honeypot(honeypot_ip, honeypot_port, pentbox_path, honeypot_timeout)
        if honeypot_process:
            print("\nHoneypot is running.  Snort should now detect traffic to it.")
            print("Press Ctrl+C to stop the honeypot.")
            try:
                # Keep the script running so the honeypot stays active.
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping Pentbox honeypot...")
                stop_pentbox_honeypot(honeypot_process)

        else:
            print("Honeypot could not be started.  Please check the error messages.")

        # Example Snort config file creation and rule management
        snort_rules = [
            "alert tcp any any -> 192.168.1.100 80 (msg:\"Web server access detected!\"; flow:established,to_server;)",
            "log udp any any -> 192.168.1.0/24 53 (msg:\"DNS query detected!\";)",
            rule  # Include the honeypot rule
        ]
        create_snort_config(snort_rules, "my_snort.conf", "/etc/snort/my_rules")
        append_snort_rule("alert icmp any any -> any any (msg:\"ICMP traffic detected!\";)", "local.rules")
        list_snort_rules("local.rules")
        list_snort_rules("nonexistent.rules") #test
    else:
        print("Failed to generate Snort rule.  Please check the errors above.")

if __name__ == "__main__":
    main()

