import json
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

from .tool import (
    get_protocol, noblankLine, readFile, b64Decode, rename, proDuplicateNodeName,
    saveFile
)
from .parsers import (
    HttpParser, HttpsParser, HysteriaParser, Hysteria2Parser,
    SocksParser, SSParser, SSRParser, TrojanParser, TUICParser, VlessParser,
    VmessParser, WireGuardParser)
from .parsers.base import ParserBase
from .parsers.clash2base64 import clash2v2ray
from .constants import DEFAULT_UA, DEFAULT_FALLBACK_UA, BUILTIN_TEMPLATE_PATH


CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

protocol_klass_map = {
    "http": HttpParser,
    "https": HttpsParser,
    "hysteria": HysteriaParser,
    "hysteria2": Hysteria2Parser,
    "socks": SocksParser,
    "ss": SSParser,
    "ssr": SSRParser,
    "trojan": TrojanParser,
    "tuic": TUICParser,
    "vless": VlessParser,
    "vmess": VmessParser,
    "wg": WireGuardParser,

    # duplicated alias
    "hy2": Hysteria2Parser,
    "socks5": SocksParser
}


class NoTemplateConfigured(Exception):
    pass


class InvalidTemplate(Exception):
    pass


class FailedToFetchSubscription(Exception):
    pass


def list_local_templates():
    template_dir = os.path.join(CURRENT_DIRECTORY, BUILTIN_TEMPLATE_PATH)
    template_files = os.listdir(template_dir)
    _template_list = [
        os.path.splitext(file)[0] for file in template_files
        if file.endswith('.json')]
    _template_list.sort()
    return _template_list


class NodeExtractor:
    def __init__(self, providers_config: dict | None = None, template=None,
                 is_console_mode=False, fetch_sub_ua=DEFAULT_UA,
                 fetch_sub_fallback_ua=DEFAULT_FALLBACK_UA,
                 export_config_folder="",
                 export_config_name="config.json"):

        if template is not None:
            providers_config["config_template"] = template

        self.providers_config = providers_config
        self.template_config = self.get_template_config()
        self._nodes = None
        self.is_console_mode = is_console_mode
        self.fetch_sub_ua = fetch_sub_ua
        self.fetch_sub_fallback_ua = fetch_sub_fallback_ua
        self._session = None
        self.config_path = self.providers_config.get(
            "save_config_path",
            os.path.join(export_config_folder, export_config_name)
        )

    @property
    def session(self):
        if self._session is None:
            self._session = requests.session()
        return self._session

    def console_print(self, str_to_print):
        if self.is_console_mode:
            print(str_to_print)

    def get_template_config(self):
        template = self.providers_config.get("config_template")
        if template is None:
            raise NoTemplateConfigured("No valid template configured")

        try:
            template_index = int(template)
            _template_list = list_local_templates()

            file_path = (
                os.path.join(
                    CURRENT_DIRECTORY,
                    BUILTIN_TEMPLATE_PATH,
                    f"{_template_list[template_index]}.json"))

            with open(file_path, "rb") as _f:
                return json.loads(_f.read())

        except ValueError:
            pass

        if template.startswith("http://") or template.startswith("https://"):  # noqa
            try:
                resp = requests.get(self.providers_config['config_template'])
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                raise InvalidTemplate(
                    f"Failed to load template: {template}: "
                    f"{type(e).__name__}: {str(e)}")

        try:
            with open(template, "rb") as f:
                return json.loads(f.read())
        except Exception as e:
            print(
                f"Failed to load {template}: "
                f"{type(e).__name__}: {str(e)}")

        raise NoTemplateConfigured("No valid template configured")

    @property
    def nodes(self):
        if self._nodes is None:
            self._nodes = self.process_nodes()

        return self._nodes

    def get_node_parser(self, node_str):
        proto = get_protocol(node_str)

        excluded_protocols = self.providers_config.get(
            'exclude_protocol', "").split(",")
        excluded_protocols = [
            ep.strip() for ep in excluded_protocols]
        if proto in excluded_protocols:
            return None

        parser_klass: ParserBase = protocol_klass_map.get(proto.lower(), None)

        if not parser_klass:
            return None

        return parser_klass

    def parse_content(self, node_list_string):
        nodelist = []
        for t in node_list_string.splitlines():
            t = t.strip()
            if not t:
                continue

            parser_klass = self.get_node_parser(t)
            if not parser_klass:
                continue

            parser_obj = parser_klass()  # noqa
            node = parser_obj.parse(t)
            if node:
                nodelist.append(node)

        return nodelist

    def get_content_from_file(self, file_path):
        self.console_print('处理: \033[31m' + file_path + '\033[0m')
        file_extension = os.path.splitext(file_path)[1]
        if file_extension.lower() in ['.yaml', '.yml']:
            with open(file_path, 'rb') as file:
                content = file.read()

            import ruamel.yaml as yaml

            yaml_data = dict(yaml.safe_load(content))
            share_links = []

            for proxy in yaml_data['proxies']:
                share_links.append(clash2v2ray(proxy))

            node = '\n'.join(share_links)
            processed_list = noblankLine(node)
            return processed_list
        else:
            data = readFile(file_path)
            data = bytes.decode(data, encoding='utf-8')
            data = noblankLine(data)
            return data

    def get_content_from_sub(self, subscribe, max_retries=6):
        url = subscribe["url"]

        self.console_print('处理: \033[31m' + url + '\033[0m')

        url_schemes = [
            "vmess://", "vless://", "ss://", "ssr://", "trojan://",
            "tuic://", "hysteria://", "hysteria2://",
            "hy2://", "wg://", "http2://", "socks://", "socks5://"]

        if any(url.startswith(prefix) for prefix in url_schemes):
            return noblankLine(url)

        user_agent = subscribe.get('User-Agent', self.fetch_sub_ua)

        n_retries = 0

        while n_retries < max_retries:
            response = None
            try:
                response = self.session.get(
                    url, headers={"User-Agent": user_agent}
                )
                response.raise_for_status()

                response_text = response.text

                if any(response_text.startswith(prefix) for prefix in url_schemes):
                    response_text = noblankLine(response_text)
                    return response_text

                elif 'proxies' in response_text:
                    import ruamel.yaml as yaml

                    yaml_content = response.content.decode('utf-8')
                    yaml_obj = yaml.YAML()
                    try:
                        response_text = dict(yaml_obj.load(yaml_content))
                        return response_text
                    except:
                        pass
                elif 'outbounds' in response_text:
                    try:
                        response_text = json.loads(response.text)
                        return response_text
                    except:
                        pass
                else:
                    try:
                        response_text = b64Decode(response_text)
                        response_text = response_text.decode(encoding="utf-8")
                    except:
                        pass
                        # traceback.print_exc()
                return response_text

            except requests.HTTPError:
                assert response is not None
                if response.status_code == 403:
                    user_agent = self.fetch_sub_fallback_ua
                    try:
                        response = self.session.get(
                            url, headers={"User-Agent": user_agent}
                        )
                        response.raise_for_status()
                    except requests.HTTPError:
                        if response.status_code == 403:
                            raise FailedToFetchSubscription(
                                f"Fetching subscription failed with 503, "
                                f"with user-agent {self.fetch_sub_ua} and "
                                f"{self.fetch_sub_fallback_ua}. Please set a valid "
                                f"fetch_sub_ua or fetch_sub_fallback_ua."
                            )
                n_retries += 1

    def get_nodes_from_sub(self, subscribe):
        url_or_path = subscribe["url"]

        if url_or_path.startswith('sub://'):
            url_or_path = b64Decode(url_or_path[6:]).decode('utf-8')

        url_str = urlparse(url_or_path)
        if not url_str.scheme:
            try:
                _content = b64Decode(url_or_path).decode('utf-8')
                data = self.parse_content(_content)
                processed_list = []
                for item in data:
                    if isinstance(item, tuple):
                        processed_list.extend([item[0], item[1]])  # 处理shadowtls
                    else:
                        processed_list.append(item)
                return processed_list
            except:
                _content = self.get_content_from_file(url_or_path)
        else:
            _content = self.get_content_from_sub(subscribe)

        # self.console_print (_content)
        if isinstance(_content, dict):
            if 'proxies' in _content:
                share_links = []
                for proxy in _content['proxies']:
                    share_links.append(clash2v2ray(proxy))
                data = '\n'.join(share_links)
                data = self.parse_content(data)
                processed_list = []
                for item in data:
                    if isinstance(item, tuple):
                        processed_list.extend([item[0], item[1]])  # 处理shadowtls
                    else:
                        processed_list.append(item)
                return processed_list
            elif 'outbounds' in _content:
                outbounds = []
                excluded_types = {"selector", "urltest", "direct", "block", "dns"}
                filtered_outbounds = [
                    outbound for outbound in _content['outbounds']
                    if outbound.get("type") not in excluded_types]
                outbounds.extend(filtered_outbounds)
                return outbounds
        else:
            assert _content is not None
            data = self.parse_content(_content)
            processed_list = []
            for item in data:
                if isinstance(item, tuple):
                    processed_list.extend([item[0], item[1]])  # 处理shadowtls
                else:
                    processed_list.append(item)
            return processed_list

    def process_nodes(self):
        def add_prefix(nodes, _subscribe):
            if _subscribe.get('prefix'):
                for node in nodes:
                    node['tag'] = _subscribe['prefix'] + node['tag']

        def add_emoji(nodes, _subscribe):
            if _subscribe.get('emoji'):
                for node in nodes:
                    node['tag'] = rename(node['tag'])

        _nodes = {}

        _providers = self.providers_config.get("subscribes", [])

        for subscribe in _providers:
            if 'enabled' in subscribe and not subscribe['enabled']:
                continue
            __nodes = self.get_nodes_from_sub(subscribe)
            if __nodes and len(__nodes) > 0:
                add_prefix(__nodes, subscribe)
                add_emoji(__nodes, subscribe)
                if not _nodes.get(subscribe['tag']):
                    _nodes[subscribe['tag']] = []
                _nodes[subscribe['tag']] += __nodes
            else:
                self.console_print('没有在此订阅下找到节点，跳过')
                # print('Không tìm thấy proxy trong link thuê bao này, bỏ qua')
        proDuplicateNodeName(_nodes)
        return _nodes

    def set_proxy_rule_dns(self):
        def pro_dns_from_route_rules(route_rule):
            dns_route_same_list = ["inbound", "ip_version", "network", "protocol",
                                   'domain', 'domain_suffix', 'domain_keyword',
                                   'domain_regex', 'geosite', "source_geoip",
                                   "source_ip_cidr", "source_port",
                                   "source_port_range", "port", "port_range",
                                   "process_name", "process_path", "package_name",
                                   "user", "user_id", "clash_mode", "invert"]
            _dns_rule_obj = {}
            for key in route_rule:
                if key in dns_route_same_list:
                    _dns_rule_obj[key] = route_rule[key]
            if len(_dns_rule_obj) == 0:
                return None
            if route_rule.get('outbound'):
                _dns_rule_obj['server'] = route_rule['outbound'] + '_dns' if \
                    route_rule['outbound'] != 'direct' else \
                    self.providers_config["auto_set_outbounds_dns"]['direct']
            return _dns_rule_obj

        # dns_template = {
        #     "tag": "remote",
        #     "address": "tls://1.1.1.1",
        #     "detour": ""
        # }
        config_rules = self.template_config['route']['rules']
        outbound_dns = []
        dns_rules = self.template_config['dns']['rules']
        asod = self.providers_config["auto_set_outbounds_dns"]
        for rule in config_rules:
            if rule['outbound'] not in ['block', 'dns-out']:
                if rule['outbound'] != 'direct':
                    outbounds_dns_template = \
                        list(filter(lambda server: server['tag'] == asod["proxy"],
                                    self.template_config['dns']['servers']))[0]
                    dns_obj = outbounds_dns_template.copy()
                    dns_obj['tag'] = rule['outbound'] + '_dns'
                    dns_obj['detour'] = rule['outbound']
                    if dns_obj not in outbound_dns:
                        outbound_dns.append(dns_obj)
                if rule.get('type') and rule['type'] == 'logical':
                    dns_rule_obj = {
                        'type': 'logical',
                        'mode': rule['mode'],
                        'rules': [],
                        'server': (
                            rule['outbound'] + '_dns'
                            if rule['outbound'] != 'direct' else asod["direct"])
                    }
                    for _rule in rule['rules']:
                        child_rule = pro_dns_from_route_rules(_rule)
                        if child_rule:
                            dns_rule_obj['rules'].append(child_rule)
                    if len(dns_rule_obj['rules']) == 0:
                        dns_rule_obj = None
                else:
                    dns_rule_obj = pro_dns_from_route_rules(rule)
                if dns_rule_obj:
                    dns_rules.append(dns_rule_obj)

        # 清除重复规则
        _dns_rules = []
        for dr in dns_rules:
            if dr not in _dns_rules:
                _dns_rules.append(dr)
        self.template_config['dns']['rules'] = _dns_rules
        self.template_config['dns']['servers'].extend(outbound_dns)

    def combine_to_config(self):
        def action_keywords(_nodes, action, keywords):
            # filter将按顺序依次执行
            # "filter":[
            #         {"action":"include","keywords":[""]},
            #         {"action":"exclude","keywords":[""]}
            #     ]
            temp_nodes = []
            flag = False
            if action == 'exclude':
                flag = True
            '''
            # 空关键字过滤
            '''
            # Join the patterns list into a single pattern, separated by '|'
            combined_pattern = '|'.join(keywords)

            # If the combined pattern is empty or only contains whitespace,
            # return the original _nodes
            if not combined_pattern or combined_pattern.isspace():
                return _nodes

            # Compile the combined regex pattern
            compiled_pattern = re.compile(combined_pattern)

            for node in _nodes:
                name = node['tag']
                # Use regex to check for a match
                match_flag = bool(compiled_pattern.search(name))

                # Use XOR to decide if the node should be included based
                # on the action
                if match_flag ^ flag:
                    temp_nodes.append(node)

            return temp_nodes

        def nodes_filter(_nodes, _filter, _group):
            for a in _filter:
                if a.get('for') and _group not in a['for']:
                    continue
                _nodes = action_keywords(_nodes, a['action'], a['keywords'])
            return _nodes

        def pro_node_template(data_nodes, config_outbound, _group):
            if config_outbound.get('filter'):
                data_nodes = nodes_filter(
                    data_nodes, config_outbound['filter'], _group)
            return [node.get('tag') for node in data_nodes]

        data = self.nodes

        config_outbounds = (
            self.template_config["outbounds"]
            if self.template_config.get("outbounds") else None)

        temp_outbounds = []
        if config_outbounds:
            # 提前处理all模板
            for po in config_outbounds:
                # 处理出站
                if po.get("outbounds"):
                    if '{all}' in po["outbounds"]:
                        o1 = []
                        for item in po["outbounds"]:
                            if item.startswith('{') and item.endswith('}'):
                                _item = item[1:-1]
                                if _item == 'all':
                                    o1.append(item)
                            else:
                                o1.append(item)
                        po['outbounds'] = o1
                    t_o = []
                    check_dup = []
                    for oo in po["outbounds"]:
                        # 避免添加重复节点
                        if oo in check_dup:
                            continue
                        else:
                            check_dup.append(oo)
                        # 处理模板
                        if oo.startswith('{') and oo.endswith('}'):
                            oo = oo[1:-1]
                            if data.get(oo):
                                nodes = data[oo]
                                t_o.extend(pro_node_template(nodes, po, oo))
                            else:
                                if oo == 'all':
                                    for group in data:
                                        nodes = data[group]
                                        t_o.extend(
                                            pro_node_template(nodes, po, group))
                        else:
                            t_o.append(oo)
                    if len(t_o) == 0:
                        self.console_print(
                            '发现 {} 出站下的节点数量为 0 ，会导致sing-box无法运行，'
                            '请检查config模板是否正确。'.format(po['tag']))

                        CONFIG_FILE_NAME = self.config_path
                        config_file_path = os.path.join('/tmp', CONFIG_FILE_NAME)
                        if os.path.exists(config_file_path):
                            os.remove(config_file_path)
                            self.console_print(f"已删除文件：{config_file_path}")
                            # print(f"Các tập tin đã bị xóa: {config_file_path}")
                        sys.exit()
                    po['outbounds'] = t_o
                    if po.get('filter'):
                        del po['filter']
        for group in data:
            temp_outbounds.extend(data[group])
        self.template_config['outbounds'] = config_outbounds + temp_outbounds

        # 自动配置路由规则到dns规则，避免dns泄露
        dns_tags = [server.get('tag') for server in
                    self.template_config['dns']['servers']]
        asod = self.providers_config.get("auto_set_outbounds_dns")
        if (asod and asod.get('proxy')
                and asod.get('direct')
                and asod['proxy'] in dns_tags
                and asod['direct'] in dns_tags):
            self.set_proxy_rule_dns()
        return self.template_config

    def write_config(self, nodes, path=None):
        path = path or self.config_path

        try:
            if ('auto_backup' in self.providers_config
                    and self.providers_config['auto_backup']):
                now = datetime.now().strftime('%Y%m%d%H%M%S')
                if os.path.exists(path):
                    os.rename(path, f'{path}.{now}.bak')
            if os.path.exists(path):
                os.remove(path)
                self.console_print(f"已删除文件，并重新保存：\033[33m{path}\033[0m")
                # print(f"File cấu hình đã được lưu vào: \033[33m{path}\033[0m")
            else:
                self.console_print(f"文件不存在，正在保存：\033[33m{path}\033[0m")
                # print(f"File không tồn tại, đang lưu tại: \033[33m{path}\033[0m")
            saveFile(path, json.dumps(nodes, indent=2, ensure_ascii=False))
        except Exception as e:
            self.console_print(f"保存配置文件时出错：{str(e)}")
            # print(f"Lỗi khi lưu file cấu hình: {str(e)}")
            # 如果保存出错，尝试使用 config_file_path 再次保存
            config_file_path = os.path.join('/tmp', self.config_path)
            try:
                if os.path.exists(config_file_path):
                    os.remove(config_file_path)
                    self.console_print(
                        f"已删除文件，并重新保存：\033[33m{config_file_path}\033[0m")
                else:
                    self.console_print(
                        f"文件不存在，正在保存：\033[33m{config_file_path}\033[0m")
                saveFile(config_file_path,
                              json.dumps(nodes, indent=2, ensure_ascii=False))
                # print(f"配置文件已保存到 {config_file_path}")
            except Exception as e:
                os.remove(config_file_path)
                self.console_print(f"已删除文件：\033[33m{config_file_path}\033[0m")
                # print(f"Các file đã bị xóa: \033[33m{config_file_path}\033[0m")
                self.console_print(f"再次保存配置文件时出错：{str(e)}")
                # print(f"Lỗi khi lưu lại file cấu hình: {str(e)}")

    def export_config(self, path=None):
        nodes_only = self.providers_config.get("Only-nodes", False)
        if not nodes_only:
            final_config = self.combine_to_config()
            return self.write_config(final_config, path)

        combined_contents = []
        for sub_tag, contents in self.nodes.items():
            # 遍历每个机场的内容
            for content in contents:
                # 将内容添加到新列表中
                combined_contents.append(content)
        final_config = combined_contents  # 只返回节点信息
        return self.write_config(final_config, path)
