import re
from urllib.parse import unquote, urlparse

from .. import tool
from .base import ParserBase


class SocksParser(ParserBase):
    @property
    def protocol_type(self):
        return "socks"

    def parse(self, data):
        info = data[:]
        server_info = urlparse(info)
        node = {
            'tag': unquote(server_info.fragment) or self.random_name,
            'type': 'socks',
            "version": "5",
            'udp_over_tcp': {}
        }
        try:
            netloc = (tool.b64_decode(server_info.netloc)).decode()
        except:
            netloc = server_info.netloc
        if '@' in netloc:
            _netloc = netloc.split("@")
            node['server'] = re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0])
            node['server_port'] = int(_netloc[1].rsplit(":", 1)[1])
            node['username'] = _netloc[0].split(":")[0]
            node['password'] = _netloc[0].split(":")[1]
        else:
            node['server'] = re.sub(r"\[|\]", "", netloc.rsplit(":", 1)[0])
            node['server_port'] = int(netloc.rsplit(":", 1)[1])
        return (node)
