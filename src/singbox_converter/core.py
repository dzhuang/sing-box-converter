import json
import logging
import os
import re
import sys
from copy import deepcopy
from urllib.parse import urlparse

import requests

from .constants import BUILTIN_TEMPLATE_PATH, DEFAULT_FALLBACK_UA, DEFAULT_UA
from .exceptions import (FailedToFetchSubscription, InvalidSubscriptionsConfig,
                         InvalidSubscriptionsJsonFile, InvalidTemplate,
                         NoTemplateConfigured, UnknownRuleSet)
from .parsers import (HttpParser, HttpsParser, Hysteria2Parser, HysteriaParser,
                      SocksParser, SSParser, SSRParser, TrojanParser,
                      TUICParser, VlessParser, VmessParser, WireGuardParser)
from .parsers.base import ParserBase
from .parsers.clash2base64 import clash2v2ray
from .tool import (b64_decode, get_protocol, proDuplicateNodeName,
                   rename_country)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


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


def list_local_templates():
    template_dir = os.path.join(CURRENT_DIRECTORY, BUILTIN_TEMPLATE_PATH)
    template_files = os.listdir(template_dir)
    _template_list = [
        os.path.splitext(file)[0] for file in template_files
        if file.endswith('.json')]
    _template_list.sort()
    return _template_list


class SingBoxConverter:
    def __init__(
            self, providers_config: dict | str, template: dict | str,
            is_console_mode=False, fetch_sub_ua=DEFAULT_UA,
            fetch_sub_fallback_ua=DEFAULT_FALLBACK_UA,
            auto_fix_empty_outbound=True,
            log_level=logging.INFO,
            disable_log=False,
    ):
        """
        :param dict | None providers_config: Configuration for providers. 
            See example at `providers example <https://raw.githubusercontent.com/dzhuang/sing-box-subscribe/main/providers-example.json>`_.
        :param template: A 0-based integer representing the index of built-in templates 
          (in alphabetical order), a URL of the template, or a file path to the 
          template, or a dict as the template config itself.
          See available templates at `built-in templates <https://github.com/dzhuang/sing-box-subscribe/tree/package/src/singbox_converter/config_template>`_.
        :type template: int, str, dict, or None
        :param bool is_console_mode: Specifies if the instance is running in console mode.
        :param str fetch_sub_ua: The User-Agent string used when fetching 
          subscriptions. Can be overridden by `User-Agent` value in `providers_config`.
        :param str fetch_sub_fallback_ua: The fallback User-Agent used when 
          requests fail with a 403 error.
        :param bool auto_fix_empty_outbound: Whether to automatically remove 
          outbounds with no nodes. Defaults to `True`.
        :param log_level: The logging level. Defaults to `logging.INFO`.
        :type log_level: logging.Level
        :param bool disable_log: If set to True, disables logging. 
          Defaults to `False`.
        """  # noqa

        self.logger = logging.getLogger(__name__)
        self.config_log(log_level, disable_log)

        self._providers_config = None
        self._providers_config_input = providers_config

        self._template_config = None
        self._template_config_input = template

        self._nodes = None
        self.is_console_mode = is_console_mode
        self.fetch_sub_ua = fetch_sub_ua
        self.fetch_sub_fallback_ua = fetch_sub_fallback_ua
        self._session = None
        self.auto_fix_empty_outbound = auto_fix_empty_outbound
        self.empty_outbound_node_tags = []

        self._singbox_config = None

    @property
    def providers_config(self):
        if self._providers_config is None:
            self.get_and_validate_providers_config()

        self.logger.debug(f"Used providers_config: \n{self._providers_config}")
        return self._providers_config

    @property
    def template_config(self):
        if self._template_config is None:
            self._template_config = self.get_template_config()

        self.logger.debug(f"Used template_config: \n{self._template_config}")
        return self._template_config

    @property
    def singbox_config(self):
        if self._singbox_config is None:
            self._singbox_config = self.combine_to_config()

        if self.logger.isEnabledFor(logging.DEBUG):
            json_str = json.dumps(self._singbox_config, indent=2)
            self.logger.debug(f"Generated config: \n{json_str}")

        return self._singbox_config

    def get_and_validate_providers_config(self):
        if isinstance(self._providers_config_input, dict):
            return self.validate_providers_config(
                p_config=self._providers_config_input)

        assert isinstance(self._providers_config_input, str), \
            (f"providers_config must be a dict or a string, "
             f"while got a {type(self._providers_config_input)}")

        try:
            with open(self._providers_config_input, "rb") as f:
                p_config = json.loads(f.read())
        except Exception as e:
            raise InvalidSubscriptionsJsonFile(
                f"Failed to load {self._providers_config_input}: "
                f"{type(e).__name__}: {str(e)}")
        else:
            return self.validate_providers_config(p_config)

    def validate_providers_config(self, p_config):
        assert isinstance(p_config, dict)

        deprecated_keys = []
        for key in ["save_config_path", "auto_backup", "Only-nodes"]:
            if key in p_config.keys():
                if p_config.pop(key) is not None:
                    deprecated_keys.append(key)

        if deprecated_keys:
            deprecated_keys_str = ", ".join([f'"{k}"' for k in deprecated_keys])
            self.logger.warning(
                f"The following keys were deprecated for providers json file"
                f"and will be ignored: {deprecated_keys_str}.")

        subscribes = p_config.get("subscribes", [])
        if not subscribes:
            raise InvalidSubscriptionsConfig(
                "The providers config must contain non empty 'subscribes'.")

        actual_subscribes = []

        for i, sub in enumerate(subscribes):
            if not isinstance(sub, dict):
                raise InvalidSubscriptionsConfig(
                    f"providers 'subscribes' {i+1} is not a dict, while got: "
                    f"{str(sub)}.")
            if "url" not in sub:
                raise InvalidSubscriptionsConfig(
                    f"providers 'subscribes' {i+1} must contain a 'url' value "
                    f"denoting the URL or local_path, while got: {str(sub)}.")

            sub.setdefault("tag", "")
            sub.setdefault("enabled", True)
            sub.setdefault("emoji", "")
            sub.setdefault("prefix", "")
            actual_subscribes.append(sub)

        p_config["subscribes"] = actual_subscribes
        self._providers_config = p_config

    def config_log(self, level, disable_log):
        if disable_log:
            self.logger.setLevel(logging.NOTSET)
            self.logger.addHandler(logging.NullHandler())
            self.logger.propagate = False
        else:
            if not self.logger.hasHandlers():
                self.logger.addHandler(logging.StreamHandler())
            self.logger.setLevel(level)

    @property
    def session(self):
        if self._session is None:
            self._session = requests.session()
        return self._session

    def console_print(self, str_to_print):
        if self.is_console_mode:
            print(str_to_print)

    def get_template_config(self):
        if self._template_config_input is None:
            raise NoTemplateConfigured("No valid template configured")

        # todo: validate template
        if isinstance(self._template_config_input, dict):
            return self._template_config_input

        try:
            template_index = int(self._template_config_input)
            _template_list = list_local_templates()

            file_path = (
                os.path.join(
                    CURRENT_DIRECTORY,
                    BUILTIN_TEMPLATE_PATH,
                    f"{_template_list[template_index]}.json"))

            self.logger.info(f"Used built-in template '{file_path}'.")

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
                    f"Failed to load template: {self._template_config_input}: "
                    f"{type(e).__name__}: {str(e)}")

        try:
            with open(self._template_config_input, "rb") as f:
                return json.loads(f.read())
        except Exception as e:
            raise InvalidTemplate(
                f"Failed to load {self._template_config_input}: "
                f"{type(e).__name__}: {str(e)}")

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
        self.logger.info(f"Getting content from {file_path}")

        file_extension = os.path.splitext(file_path)[1]
        if file_extension.lower() in ['.yaml', '.yml']:
            with open(file_path, 'rb') as file:
                content = file.read()

            import ruamel.yaml as yaml

            yaml_data = dict(yaml.safe_load(content))
            share_links = []

            for proxy in yaml_data['proxies']:
                share_links.append(clash2v2ray(proxy))

            return '\n'.join([line.strip() for line in share_links if line.strip()])
        else:
            with open(file_path, "r") as f:
                data = f.read()

            return "\n".join([
                line.strip() for line in data.splitlines() if line.strip()])

    def get_content_from_sub(self, subscribe, max_retries=6):
        url = subscribe["url"]

        self.console_print('处理: \033[31m' + url + '\033[0m')
        self.logger.info(f"Getting content from {url}")

        url_schemes = [
            "vmess://", "vless://", "ss://", "ssr://", "trojan://",
            "tuic://", "hysteria://", "hysteria2://",
            "hy2://", "wg://", "http2://", "socks://", "socks5://"]

        if any(url.startswith(prefix) for prefix in url_schemes):
            return "\n".join(
                [l.strip() for l in url.splitlines() if l.strip()])

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
                    return "\n".join(
                        [l.strip() for l in response_text.splitlines() if l.strip()])

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
                        response_text = b64_decode(response_text)
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
            url_or_path = b64_decode(url_or_path[6:]).decode('utf-8')

        url_str = urlparse(url_or_path)
        if not url_str.scheme:
            try:
                _content = b64_decode(url_or_path).decode('utf-8')
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
                    node['tag'] = rename_country(node['tag'])

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

                self.logger.warning(
                    f"No nodes found in {subscribe['tag']}, skipped.")

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
        config_rules = self._singbox_config['route']['rules']
        outbound_dns = []
        dns_rules = self._singbox_config['dns']['rules']
        asod = self.providers_config["auto_set_outbounds_dns"]
        for rule in config_rules:
            if rule['outbound'] not in ['block', 'dns-out']:
                if rule['outbound'] != 'direct':
                    outbounds_dns_template = \
                        list(filter(lambda server: server['tag'] == asod["proxy"],
                                    self._singbox_config['dns']['servers']))[0]
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
        self._singbox_config['dns']['rules'] = _dns_rules
        self._singbox_config['dns']['servers'].extend(outbound_dns)

    def combine_to_config(self):
        self._singbox_config = self.template_config

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
            self._singbox_config["outbounds"]
            if self._singbox_config.get("outbounds") else None)

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
                        if self.auto_fix_empty_outbound:
                            po['outbounds'] = t_o
                            if po.get('filter'):
                                del po['filter']

                            self.empty_outbound_node_tags.append(po['tag'])
                            continue

                        self.console_print(
                            '发现 {} 出站下的节点数量为 0 ，会导致sing-box无法运行，'
                            '请检查config模板是否正确。'.format(po['tag']))

                        self.logger.warning(
                            f"{po['tag']} has no outbound nodes, that will cause "
                            f"failure, please check if the config template is "
                            f"correct or try to set auto_fix_empty_outbound=True.")

                        CONFIG_FILE_NAME = self.config_path
                        config_file_path = os.path.join('/tmp', CONFIG_FILE_NAME)
                        if os.path.exists(config_file_path):
                            os.remove(config_file_path)
                            self.console_print(f"已删除文件：{config_file_path}")
                        sys.exit()
                    po['outbounds'] = t_o
                    if po.get('filter'):
                        del po['filter']
        for group in data:
            temp_outbounds.extend(data[group])
        self._singbox_config['outbounds'] = config_outbounds + temp_outbounds

        # 自动配置路由规则到dns规则，避免dns泄露
        dns_tags = [server.get('tag') for server in
                    self._singbox_config['dns']['servers']]
        asod = self.providers_config.get("auto_set_outbounds_dns")
        if (asod and asod.get('proxy')
                and asod.get('direct')
                and asod['proxy'] in dns_tags
                and asod['direct'] in dns_tags):
            self.set_proxy_rule_dns()

        self.remove_empty_bound_nodes()

        self.validate_rule_set()
        self.validate_outbound_tags()

        return self._singbox_config

    def remove_empty_bound_nodes(self):
        if not self.auto_fix_empty_outbound:
            return

        root_outbounds = deepcopy(self._singbox_config.get("outbounds", []))

        while len(self.empty_outbound_node_tags):
            _tag = self.empty_outbound_node_tags.pop(0)
            new_root_outbounds = []
            for ob in root_outbounds:
                if ob["tag"] == _tag:
                    self.logger.warning(
                        f"'{_tag}' was removed from outbounds because it does not "
                        f"contain any child outbound nodes.")
                    continue
                this_outbounds = ob.get("outbounds", None)
                if this_outbounds is not None:
                    if not isinstance(this_outbounds, list):
                        this_outbounds = [this_outbounds]

                    this_outbounds = [tag for tag in this_outbounds
                                      if tag != _tag]
                    ob["outbounds"] = this_outbounds
                    if len(ob["outbounds"]) == 0:
                        self.empty_outbound_node_tags.append(ob["tag"])

                if ob.get("default") == _tag:
                    ob.pop("default")
                    self.logger.warning(
                        f"outbound '{ob['tag']}' remove the default outbound node "
                        f"'{_tag}' which does not "
                        f"contain any child outbound nodes.")

                new_root_outbounds.append(ob)

            root_outbounds = new_root_outbounds

        self._singbox_config["outbounds"] = root_outbounds

    def validate_rule_set(self):
        route = self._singbox_config.get("route", {})
        rules = route.get("rules", [])

        used_rule_set = set()
        for rule in rules:
            rule_set = rule.get("rule_set", None)
            if not rule_set:
                continue

            if not isinstance(rule_set, list):
                rule_set = [rule_set]

            used_rule_set.update(rule_set)

        rule_set_config = route.get("rule_set", [])

        configured_rule_set_tags = [rs["tag"] for rs in rule_set_config]

        unknown_rule_sets = list(used_rule_set.difference(
            set(configured_rule_set_tags)))

        if unknown_rule_sets:
            unknowns = ", ".join(unknown_rule_sets)
            raise UnknownRuleSet(f"Unknown rule_set: {unknowns}")

        unused_rule_sets = list(
            set(configured_rule_set_tags).difference(used_rule_set))

        if unused_rule_sets:
            new_rule_set = [rs for rs in rule_set_config
                            if rs["tag"] not in unused_rule_sets]

            self._singbox_config["route"]["rule_set"] = new_rule_set

            unused_rule_set_str = ", ".join(unused_rule_sets)
            self.logger.warning(
                f"The following rule_set were not referenced and were "
                f"removed from the generated config: {unused_rule_set_str}")

    def validate_outbound_tags(self):
        unknowns = []
        used_outbounds = set()

        root_outbounds = self._singbox_config.get("outbounds", [])

        available_ob_tags = [ob["tag"] for ob in root_outbounds]

        route_config = self._singbox_config.get("route", {})
        route_rules = route_config.get("rules", [])
        route_rules_outbounds = [rr["outbound"] for rr in route_rules]
        used_outbounds.update(route_rules_outbounds)

        unknown_rr_ob_tags = (
            set(route_rules_outbounds).difference(set(available_ob_tags)))

        if unknown_rr_ob_tags:
            unknowns.append({
                "configure_item": "router",
                "value": list(unknown_rr_ob_tags),
                "location": "outbound"})

        final_route = route_config.get("final", "").strip()
        if final_route:
            assert isinstance(final_route, str)
            if final_route not in available_ob_tags:
                unknowns.append({
                    "configure_item": "router",
                    "value": list(unknown_rr_ob_tags),
                    "location": "final"})

            used_outbounds.add(final_route)

        rule_sets = self._singbox_config.get("rule_set", [])
        rule_set_download_detour = [rs["download_detour"] for rs in rule_sets]
        used_outbounds.update(rule_set_download_detour)

        unknown_rs_ob_tags = (
            set(rule_set_download_detour).difference(set(available_ob_tags)))

        if unknown_rr_ob_tags:
            unknowns.append({
                "configure_item": "rule_set",
                "value": list(unknown_rs_ob_tags),
                "location": "download_detour"})

        dns_servers = self._singbox_config.get("dns", {}).get("servers", [])
        dns_servers_detour = [
            ds.get("detour") for ds in dns_servers if "detour" in ds]
        used_outbounds.update(dns_servers_detour)

        unknown_ds_ob_tags = (
            set(dns_servers_detour).difference(set(available_ob_tags)))

        if unknown_ds_ob_tags:
            unknowns.append({
                "configure_item": "dns['servers']",
                "value": list(unknown_ds_ob_tags),
                "location": "detour"})

        for ob in root_outbounds:
            if "outbounds" not in ob:
                continue
            sub_outbounds = ob["outbounds"]
            _unknown_sub_ob_tags = (
                set(sub_outbounds).difference(set(available_ob_tags)))

            if _unknown_sub_ob_tags:
                unknowns.append({
                    "configure_item": f"outbounds item tagged '{ob['tag']}'",
                    "value": _unknown_sub_ob_tags,
                    "location": "outbounds"})

            used_outbounds.update(sub_outbounds)

        unused_outbounds = set(available_ob_tags).difference(used_outbounds)

        if unused_outbounds:
            unused_outbounds_str = ", ".join(
                [f'"{tag}"' for tag in unused_outbounds])
            self.logger.warning(
                f"The following outbound tags were not used: "
                f"{unused_outbounds_str}")

        if unknowns:
            msgs = []
            for unknown in unknowns:
                unknown_value = ', '.join(f'"{v}"' for v in unknown['value'])
                msgs.append(
                    f"The following outbounds tags set in "
                    f"{unknown['configure_item']} at '{unknown['location']}' "
                    f"are unknown: "
                    f"{unknown_value}")

            raise InvalidTemplate("\n".join(msgs))

    def export_config(self, path, nodes_only=False):

        if not nodes_only:
            content = self.singbox_config

        else:
            content = []
            for sub_tag, nodes in self.nodes.items():
                # 遍历每个机场的内容
                for node_dict in nodes:
                    # 将内容添加到新列表中
                    content.append(node_dict)

        with open(path, mode='w', encoding='utf-8') as f:
            f.write(json.dumps(content, indent=2, ensure_ascii=False))
