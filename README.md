# SingBox Converter

The code are refactored from [Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe) See [Documentation](https://github.com/Toperlock/sing-box-subscribe/blob/main/instructions/README.md).

## How to install

```bash
pip install PySingBoxConverter
```

## Use in commandline

#### Create a `providers.json` from [`providers-example.json`](https://raw.githubusercontent.com/dzhuang/sing-box-subscribe/main/providers-example.json):

```bash
cp providers-example.json providers.json

vi providers.json
```

#### Then run

```bash
singbox_convert -t 1 -o config1.json
```

## Use in python code systematically

```python
from singbox_converter import SingBoxConverter

converter = SingBoxConverter(
    providers_config="/path/to/providers.json",
    template="/path/to/template",
    fetch_sub_ua="clash.meta",
    # fetch_sub_fallback_ua="clash",
    # export_config_folder="",
    # export_config_name="my_config.json",
    # auto_fix_empty_outbound=True,
)

print(converter.singbox_config)

converter.export_config(
    path="/path/to/output/config",
    # nodes_only=True
)

```


## Thanks
Credit goes to:
- [Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe)
- [gg4924/sing-box-subscribe](https://github.com/gg4924/sing-box-subscribe)
