import re


class CidrMaskConvert:
    def cidr_to_mask(self, cidr):
        # valdating CIDR value
        if not isinstance(cidr, int):
            try:
                cidr = int(cidr)
            except ValueError:
                return "CIDR prefix must be an integer"
        if cidr < 0 or cidr > 32:
            return "CIDR prefix must be between 0 and 32 inclusive"
        binary_str = "1" * cidr + "0" * (32 - cidr)
        # splitting binary string into 4 parts of 8 bits each
        parts = [binary_str[i : i + 8] for i in range(0, 32, 8)]
        # converting each 8-bit part to decimal
        decimal_parts = [int(part, 2) for part in parts]
        # joining decimal parts with dots to form netmask
        netmask = ".".join(str(part) for part in decimal_parts)
        return netmask

    def mask_to_cidr(self, cidr_prefix):
        # split netmask into 4 parts
        is_valid = IpValidate().ipv4_validation(cidr_prefix)
        if is_valid:
            parts = cidr_prefix.split(".")
            # convert each part (p) to binary and concatenate
            binary_str = "".join([bin(int(p))[2:].zfill(8) for p in parts])

            # count the number of '1's in the binary string
            cidr = len(binary_str.rstrip("0"))

            return cidr
        return "Invalid IP"


class IpValidate:
    def ipv4_validation(self, cidr_prefix):
        # defining a regular expression to match valid IPv4 addresses
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        # checking whether the input string matches the pattern
        if not re.match(pattern, cidr_prefix):
            return False
        # splitting the input string and validate each part
        parts = cidr_prefix.split(".")
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
