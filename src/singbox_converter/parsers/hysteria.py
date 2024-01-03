import re
from urllib.parse import parse_qs, unquote, urlparse

from .. import tool
from .base import ParserBase


class HysteriaParser(ParserBase):
    def parse(self, data):
        info = data[:]
        server_info = urlparse(info)
        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(server_info.query).items()
        )
        node = {
            'tag': unquote(server_info.fragment) or tool.generate_random_name() + '_hysteria',
            'type': 'hysteria',
            'server': re.sub(r"\[|\]", "", server_info.netloc.rsplit(":", 1)[0]),
            'server_port': int(server_info.netloc.rsplit(":", 1)[1]),
            'up_mbps': int(re.search(r'\d+', netquery.get('upmbps', '10')).group()),
            'down_mbps': int(re.search(r'\d+', netquery.get('downmbps', '100')).group()),
            'auth_str': netquery.get('auth', ''),
            'tls': {
                'enabled': True,
                'server_name': netquery.get('sni', netquery.get('peer', ''))
            }
        }
        node['tls']['alpn'] = (netquery.get('alpn') or "h3").strip('{}').split(',')
        if netquery.get('insecure') == '1' or netquery.get('allowInsecure') == '1':
            node['tls']['insecure'] = True
        if netquery.get('obfs') and netquery['obfs'] != 'none':
            node['obfs'] = netquery.get('obfs')
        return node
