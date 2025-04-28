import re  # Import the regular expression module
import ipaddress # Import the ipaddress module

def validate_ip_address(ip_address_string):
    """
    Validates if a given string is a valid IPv4 or IPv6 address.

    Args:
        ip_address_string (str): The string to validate.

    Returns:
        bool: True if the string is a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address_string)
        return True
    except ValueError:
        return False

def validate_port(port):
    """
    Validates if a given port number is within the valid range (1-65535).

    Args:
        port (int): The port number to validate.

    Returns:
        bool: True if the port number is valid, False otherwise.
    """
    return 1 <= port <= 65535

def validate_protocol(protocol):
    """
    Validates if a given protocol is a valid Snort protocol.

    Args:
        protocol (str): The protocol string to validate.

    Returns:
        bool: True if the protocol is valid, False otherwise.
    """
    valid_protocols = ["tcp", "udp", "icmp", "ip", "http"] # Extend this list as needed
    return protocol.lower() in valid_protocols

def validate_action(action):
    """
    Validates if a given action is a valid Snort action.

    Args:
        action (str): The action string to validate.

    Returns:
        bool: True if the action is valid, False otherwise.
    """
    valid_actions = ["alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"]
    return action.lower() in valid_actions

def validate_direction(direction):
    """
    Validates the direction operator.

    Args:
        direction (str): The direction string

    Returns:
        bool: True if the direction is valid, False otherwise.
    """
    valid_directions = ["->", "<-", "<>"]
    return direction in valid_directions

def escape_content(content):
    """
    Escapes special characters in the content string for Snort rules.

    Args:
        content (str): The content string to escape.

    Returns:
        str: The escaped content string.
    """
    escaped_content = content.replace("|", "||").replace(";", "\\;")  # Escape pipe and semicolon
    escaped_content = re.sub(r"[\x00-\x1f\x7f]", lambda m: f"|{ord(m.group(0)):02x}|", escaped_content) # Escape non-printable
    return escaped_content

def generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, options=None):
    """
    Generates a Snort rule string based on the provided parameters.

    Args:
        action (str): The action to take (e.g., "alert", "log", "drop").
        protocol (str): The protocol (e.g., "tcp", "udp", "icmp").
        src_ip (str): The source IP address or network (e.g., "192.168.1.0/24", "!192.168.1.1").
        src_port (str): The source port (e.g., "any", "80", "[100:200]", "!80").
        direction (str): The traffic direction ("->", "<-", "<>").
        dest_ip (str): The destination IP address or network.
        dest_port (str): The destination port.
        options (dict, optional): A dictionary of Snort rule options (e.g., {"msg": "Possible attack!", "flow": "established"}).
                         Defaults to None.

    Returns:
        str: The generated Snort rule string.  Returns an empty string "" if there are validation errors.
    """
    # Input validation
    if not validate_action(action):
        print(f"Error: Invalid action '{action}'.")
        return ""
    if not validate_protocol(protocol):
        print(f"Error: Invalid protocol '{protocol}'.")
        return ""
    if not validate_direction(direction):
        print(f"Error: Invalid direction '{direction}'.")
        return ""

    # Basic validation of IP addresses.  More complex validation is possible.
    if not (src_ip == "any" or validate_ip_address(src_ip) or "/" in src_ip or src_ip.startswith("!")):
          print(f"Error: Invalid source IP address '{src_ip}'.")
          return ""
    if not (dest_ip == "any" or validate_ip_address(dest_ip) or "/" in dest_ip or dest_ip.startswith("!")):
          print(f"Error: Invalid destination IP address '{dest_ip}'.")
          return ""

    #check port
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
            # Handle 'content' option:  Escape special characters.
            if key == "content":
                value = f'"{escape_content(value)}"'
            elif key in ["offset", "depth", "within", "distance"]:
                try:
                  int(value) #check if the value is an int
                except ValueError:
                    print(f"Error: The value for '{key}' must be an integer.  Value provided: '{value}'")
                    return ""
            elif key == "http_uri":
                 value = f'"{escape_content(value)}"'
            elif key == "http_header":
                 value = f'"{escape_content(value)}"'
            elif key == "rawbytes":
                if value not in ["", " "]: # Value can be empty
                    print(f"Error: The value for '{key}' must be empty. Value provided: '{value}'")
                    return ""
            option_strings.append(f"{key}:{value};")
        rule += " ".join(option_strings)
        rule += ")"

    return rule

def main():
    """
    Main function to demonstrate the usage of the generate_snort_rule function.
    """
    # Example usage:
    action = "alert"
    protocol = "tcp"
    src_ip = "192.168.1.0/24"
    src_port = "any"
    direction = "->"
    dest_ip = "10.0.0.0/24"
    dest_port = "!80"
    options = {
        "msg": "Possible SQL Injection Attempt",
        "flow": "established,to_server",
        "content": "SELECT * FROM",
        "depth": 10,
        "offset": 0,
        "http_uri": "/login.php",
        "http_header": "User-Agent: BadBot",
        "rawbytes": ""
    }

    rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, options)
    if rule:
        print("Generated Snort Rule:")
        print(rule)

    # Example with invalid action
    invalid_rule = generate_snort_rule("invalid_action", protocol, src_ip, src_port, direction, dest_ip, dest_port, options)
    if not invalid_rule:
        print("\n(Expected) Error: Invalid action was caught.")

    # Example with invalid IP address
    invalid_ip_rule = generate_snort_rule(action, protocol, "256.256.256.256", src_port, direction, dest_ip, dest_port, options)
    if not invalid_ip_rule:
        print("\n(Expected) Error: Invalid IP address was caught.")

    # Example with invalid port
    invalid_port_rule = generate_snort_rule(action, protocol, src_ip, "65536", direction, dest_ip, dest_port, options)
    if not invalid_port_rule:
        print("\n(Expected) Error: Invalid port was caught.")

    # Example with invalid protocol
    invalid_protocol_rule = generate_snort_rule(action, "invalid_protocol", src_ip, src_port, direction, dest_ip, dest_port, options)
    if not invalid_protocol_rule:
        print("\n(Expected) Error: Invalid protocol was caught.")

    # Example with invalid direction
    invalid_direction_rule = generate_snort_rule(action, protocol, src_ip, src_port, "invalid_direction", dest_ip, dest_port, options)
    if not invalid_direction_rule:
        print("\n(Expected) Error: Invalid direction was caught.")

    # Example with non-integer for depth
    invalid_option_value_rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, {"msg": "Test", "depth": "abc"})
    if not invalid_option_value_rule:
        print("\n(Expected) Error: Invalid option value for 'depth' was caught.")

    # Example with invalid http_header
    invalid_http_header_rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, {"msg": "Test", "http_header": "User-Agent:\x01BadBot"})
    if not invalid_http_header_rule:
        print("\n(Expected) Error: Invalid option value for 'http_header' was caught.")

    # Example with invalid rawbytes value
    invalid_rawbytes_rule = generate_snort_rule(action, protocol, src_ip, src_port, direction, dest_ip, dest_port, {"msg": "Test", "rawbytes": "123"})
    if not invalid_rawbytes_rule:
        print("\n(Expected) Error: Invalid option value for 'rawbytes' was caught.")

if __name__ == "__main__":
    main()
