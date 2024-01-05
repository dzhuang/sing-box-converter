import base64
import random
import re
import string

from singbox_converter.constants import RENAME_COUNTRY_REGEX_PATTERNS


def rename_country(input_str):
    for country_code, pattern in RENAME_COUNTRY_REGEX_PATTERNS.items():
        if input_str.startswith(country_code):
            return country_code + ' ' + input_str[len(country_code):].strip()
        if pattern.search(input_str):
            if input_str.startswith('🇺🇲'):
                return country_code + ' ' + input_str[len('🇺🇲'):].strip()
            else:
                return country_code + ' ' + input_str
    return input_str


def b64_decode(_str):
    _str = _str.strip()
    _str += (len(_str) % 4) * '='
    return base64.urlsafe_b64decode(_str)


def generate_random_name(length=8):
    name = ''
    for i in range(length):
        name += random.choice(string.ascii_letters+string.digits)
    return name


def get_protocol(s):
    protocol_map = {
        'hy2': 'hysteria2',
        'http2': 'http',
        'socks5': 'socks'
    }

    m = re.search(r'^(.+?)://', s)
    if m:
        protocol = m.group(1)
        return protocol_map.get(protocol, protocol)
    return None
