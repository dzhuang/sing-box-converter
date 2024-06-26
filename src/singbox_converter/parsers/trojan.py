import re
from urllib.parse import parse_qs, unquote, urlparse

from .. import tool
from .base import ParserBase


class TrojanParser(ParserBase):
    def parse(self, data):
        info = data[:]
        server_info = urlparse(info)
        if server_info.path:
          server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
        if '@' in server_info.netloc:
            _netloc = server_info.netloc.split("@")
        else:
            return None
        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(server_info.query).items()
        )
        node = {
            'tag': unquote(server_info.fragment) or tool.generate_random_name() + '_trojan',
            'type': 'trojan',
            'server': re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0]),
            'server_port': int(_netloc[1].rsplit(":", 1)[1].split("/")[0]),
            'password': _netloc[0],
            'tls': {
                'enabled': True,
                'insecure': False
            }
        }
        if netquery.get('allowInsecure') and netquery['allowInsecure'] == '1' :
            node['tls']['insecure'] = True
        if netquery.get('alpn'):
            node['tls']['alpn'] = netquery.get('alpn').strip('{}').split(',')
        if netquery.get('sni'):
            node['tls']['server_name'] = netquery.get('sni', '')
        if netquery.get('fp'):
            node['tls']['utls'] = {
                'enabled': True,
                'fingerprint': netquery.get('fp')
            }
        if netquery.get('type'):
            if netquery['type'] == 'h2':
                node['transport'] = {
                    'type':'http',
                    'host':netquery.get('host', node['server']),
                    'path':netquery.get('path', '/')
                }
            if netquery['type'] == 'ws':
                if netquery.get('host'):
                    node['transport'] = {
                         'type':'ws',
                         'path':netquery.get('path', '/'),
                         'headers': {
                             'Host': netquery.get('host')
                        }
                    }
            if netquery['type'] == 'grpc':
                node['transport'] = {
                    'type':'grpc',
                    'service_name':netquery.get('serviceName', '')
                }
        if netquery.get('protocol'):
            node['multiplex'] = {
                'enabled': True,
                'protocol': netquery['protocol'],
                'max_streams': int(netquery.get('max_streams', '0'))
            }
            if netquery.get('max_connections'):
                node['multiplex']['max_connections'] = int(netquery['max_connections'])
            if netquery.get('min_streams'):
                node['multiplex']['min_streams'] = int(netquery['min_streams'])
            if netquery.get('padding') == 'True':
                node['multiplex']['padding'] = True
        return node
