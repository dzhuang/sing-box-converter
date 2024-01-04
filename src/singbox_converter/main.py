import argparse
import os
import sys

from .core import SingBoxConverter, list_local_templates


def display_template(template_list):
    color_code = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]

    for idx, tmpl in enumerate(template_list):
        print_str = f"\033[{color_code[idx]}m {idx}: {tmpl} \033[0m"
        print(print_str)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", '--template', help='template path or url or index')
    parser.add_argument(
        "-o", '--output_path', required=True,
        help='export path of generated config')
    parser.add_argument(
        "-f", '--providers_json_path', required=False,
        default="providers.json",
        help='path to providers config json file')
    parser.add_argument(
        "-n", '--nodes_only', required=False, default=False,
        help='only export nodes')
    parser.add_argument(
        "--force_overwrite", required=False, default=False,
        help='if the output_path exist, whether overwrite that file')

    args = parser.parse_args()

    template = args.template

    if template is None:
        print("Note: 'template' not configured, please select one")
        template_list = list_local_templates()
        if len(template_list) < 1:
            print('没有找到模板文件')
            sys.exit()
        display_template(template_list)
        while True:
            try:
                template = input(
                    '输入序号，载入对应config模板（直接回车默认选第一个配置模板）：')

                if template == '':
                    template = 0

                else:
                    template = int(template)

                if template > len(template_list):
                    raise ValueError()

                print('选择: \033[33m' + template_list[template] + '.json\033[0m')
                break
            except Exception:  # noqa
                print('输入了错误信息！重新输入')

    output_path = args.output_path

    directory = os.path.dirname(output_path)
    if directory.strip():
        if not os.path.exists(directory):
            raise FileNotFoundError(
                f"The directory '{directory}' does not exist.")

    converter = SingBoxConverter(
        providers_config=args.providers_json_path,
        template=template,
        is_console_mode=True)

    if os.path.exists(output_path):
        if not args.force_overwrite:
            raise FileExistsError(f"A file already exists: '{output_path}'.")
        else:
            try:
                os.remove(output_path)
            except Exception as e:
                print(
                    f"Failed to remove {output_path}: {type(e).__name__}: {str(e)}")
                exit(1)

    converter.export_config(output_path, nodes_only=args.nodes_only)
    print(f"Done generating {output_path}.")


if __name__ == '__main__':
    main()
