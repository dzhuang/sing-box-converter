# SingBox Converter

The code are refactored from [Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe) See [Documentation](https://github.com/Toperlock/sing-box-subscribe/blob/main/instructions/README.md).

## How to install

```bash
pip install git+https://github.com/dzhuang/sing-box-subscribe.git@package
```

## Use in commandline

#### Create a `providers.json` from [`providers-example.json`](https://raw.githubusercontent.com/dzhuang/sing-box-subscribe/main/providers-example.json):

```bash
cp providers-example.json providers.json

vi providers.json
```

#### Then run

```bash
singbox_converter
```

## Use in python code systematically

```python

import json
from singbox_converter import NodeExtractor

with open("/path/to/providers.json", "rb") as f:
    config = json.loads(f.read())

extractor = NodeExtractor(
    providers_config=config,
    template="/path/to/template",
    fetch_sub_ua="clash.meta",
    # fetch_sub_fallback_ua="clash",
    # export_config_folder="",
    # export_config_name="my_config.json"
)

extractor.export_config(
    # path="/path/to/output/config"
)

```


## Thanks
Credit goes to [Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe).