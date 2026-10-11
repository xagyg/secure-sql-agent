# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Shared helpers for the YAML configuration files:
#
#   config/security/<database>.yaml   who may see what (controls/security_policy.py)
#   config/semantic/<database>/       what the data means (adaptive/semantic_model.py)
#
# One security file and one semantic folder per database; the defaults
# are the Northwind demo's (DEFAULT_DATABASE).
#
# Both are read with yaml.safe_load (no Python objects can be built from
# the file) and a loader that REJECTS duplicate keys. PyYAML's default is
# to keep the last duplicate silently, so a second "demo:" role further
# down the file would quietly replace the first one's grants and denies.

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"

# The database whose configuration is used when no path is given.
DEFAULT_DATABASE = "northwind"


class ConfigFileError(ValueError):
    """A configuration file is missing, unreadable or invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            mark = key_node.start_mark
            raise yaml.constructor.ConstructorError(
                None, None,
                f"duplicate key {key!r} (line {mark.line + 1})",
                mark,
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(path):
    """
    Read one YAML file as a dict. An empty file is an empty dict. Raises
    ConfigFileError for a YAML syntax error, a duplicate key or a top
    level that isn't a mapping.
    """
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.load(handle, Loader=_UniqueKeyLoader)
    except OSError as ex:
        raise ConfigFileError(f"{path}: cannot read file ({ex})") from ex
    except yaml.YAMLError as ex:
        raise ConfigFileError(f"{path}: invalid YAML: {ex}") from ex

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigFileError(f"{path}: the top level must be a mapping")
    return data


def format_validation_error(path, error):
    """A pydantic ValidationError as short "path: where: problem" lines."""
    lines = []
    for item in error.errors():
        where = ".".join(str(part) for part in item["loc"]) or "(top level)"
        lines.append(f"  {where}: {item['msg']}")
    return f"{path}: invalid configuration\n" + "\n".join(lines)
