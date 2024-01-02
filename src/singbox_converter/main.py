import json, tool, requests, sys, argparse
from dispatch import NodeExtractor, list_local_templates


def load_json(path):
    return json.loads(tool.readFile(path))


def update_local_config(local_host, path):
    header = {
        'Content-Type': 'application/json'
    }
    r = requests.put(
        local_host + '/configs?force=false', json={"path": path}, headers=header)
    print(r.text)


def display_template(tl):
    def loop_color(text):
        color_code = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]
        text = '\033[1;{color}m{text}\033[0m'.format(color=color_code[0], text=text)
        color_code.append(color_code.pop(0))
        return text

    print_str = ''
    for i in range(len(tl)):
        print_str += loop_color('{index}、{name} '.format(index=i + 1, name=tl[i]))
    print(print_str)


def select_config_template(tl, selected_template_index=None):
    if args.template_index is not None:
        _uip = args.template_index
    else:
        # print ('Nhập số để chọn mẫu cấu hình tương ứng (nhấn Enter để chọn mẫu cấu hình đầu tiên theo mặc định): ')
        _uip = input('输入序号，载入对应config模板（直接回车默认选第一个配置模板）：')
        try:
            if _uip == '':
                return 0
            _uip = int(_uip)
            if _uip < 1 or _uip > len(tl):
                print('输入了错误信息！重新输入')
                # print('Nhập thông tin không chính xác! Vui lòng nhập lại')
                return select_config_template(tl)
            else:
                _uip -= 1
        except:
            print('输入了错误信息！重新输入')
            # print('Nhập thông tin không chính xác! Vui lòng nhập lại')
            return select_config_template(tl)
    return _uip


# 自定义函数，用于解析参数为 JSON 格式
def parse_json(value):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        raise argparse.ArgumentTypeError(f"Invalid JSON: {value}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--temp_json_data', type=parse_json, help='临时内容')
    parser.add_argument('--template_index', type=int, help='模板序号')
    args = parser.parse_args()
    temp_json_data = args.temp_json_data
    config = None

    if temp_json_data and temp_json_data != '{}':
        providers = json.loads(temp_json_data)

    else:
        providers = load_json('providers.json')  # 加载本地 providers.json
    if providers.get('config_template'):
        config_template_path = providers['config_template'].strip()
        print('选择: \033[33m' + config_template_path + '\033[0m')

    else:
        template_list = list_local_templates()
        if len(template_list) < 1:
            print('没有找到模板文件')
            # print('Không tìm thấy file mẫu')
            sys.exit()
        display_template(template_list)
        uip = select_config_template(
            template_list, selected_template_index=args.template_index)
        print('选择: \033[33m' + template_list[uip] + '.json\033[0m')

        providers["config_template"] = uip

    extractor = NodeExtractor(providers_config=providers, is_console_mode=True)
    # update_local_config('http://127.0.0.1:9090',providers['save_config_path'])
    extractor.export_config()
