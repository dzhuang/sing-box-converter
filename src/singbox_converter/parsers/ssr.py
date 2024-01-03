from .. import tool
from .base import ParserBase


class SSRParser(ParserBase):
    def parse(self, data):
        info = data[6:]
        if not info or info.isspace():
            return None
        proxy_str = tool.b64_decode(info).decode('utf-8')
        parts = proxy_str.split(':')
        if len(parts) != 6:
            return None
        node = {
            'tag':None,
            'type':'shadowsocksr',
            'server': parts[0],
            'server_port': int(parts[1]),
            'protocol': parts[2],
            'method': parts[3],
            'obfs': parts[4]
        }
        password_params = parts[5].split('/?')
        node['password'] = tool.b64_decode(password_params[0]).decode('utf-8')
        params = password_params[1].split('&')
        pdict = {'obfsparam':'obfs_param','protoparam':'protocol_param','remarks':'tag'}
        for p in params:
            key_value = p.split('=')
            keyname = key_value[0]
            if keyname in pdict.keys():
                keyname = pdict[keyname]
                node[keyname] = tool.b64_decode(key_value[1]).decode('utf-8')
        node['tag'] = node['tag'] if node.get('tag') else tool.generate_random_name() + '_shadowsocksr'
        return node
