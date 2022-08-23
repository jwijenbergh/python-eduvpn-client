"""
This module contains code to maintain a simple metadata storage in ~/.config/eduvpn/
"""
import json
import eduvpn
from os import PathLike
from typing import Optional
from eduvpn.settings import CONFIG_PREFIX, CONFIG_DIR_MODE
from eduvpn.ovpn import Ovpn
from eduvpn.utils import get_logger

logger = get_logger(__name__)


def get_setting(what: str) -> Optional[str]:
    p = (CONFIG_PREFIX / what).expanduser()
    if p.exists():
        return open(p, "r").read().strip()
    else:
        return None


def is_config_dir_permissions_correct() -> bool:
    return CONFIG_PREFIX.stat().st_mode & 0o777 == CONFIG_DIR_MODE


def check_config_dir_permissions():
    if not is_config_dir_permissions_correct():
        logger.warning(
            f"The permissions for the config dir ({CONFIG_PREFIX}) "
            f"are not as expected, it may be world readable!"
        )


def ensure_config_dir_exists():
    """
    Ensure the config directory exists with the correct permissions.
    """
    CONFIG_PREFIX.mkdir(parents=True, exist_ok=True, mode=CONFIG_DIR_MODE)
    check_config_dir_permissions()


def set_setting(what: str, value: str):
    p = (CONFIG_PREFIX / what).expanduser()
    ensure_config_dir_exists()
    with open(p, "w") as f:
        f.write(value)


def write_ovpn(ovpn: Ovpn, private_key: str, certificate: str, target: PathLike):
    """
    Write the OVPN configuration file to target.
    """
    _logger.info(f"Writing configuration to {target}")
    with open(target, mode="w+t") as f:
        ovpn.write(f)
        f.writelines(f"\n<key>\n{private_key}\n</key>\n")
        f.writelines(f"\n<cert>\n{certificate}\n</cert>\n")


def get_uuid() -> Optional[str]:
    """
    Read the UUID of the last generated eduVPN Network Manager connection.
    """
    return get_setting("uuid")


def set_uuid(uuid: str):
    """
    Write the eduVPN network manager connection UUID to disk.
    """
    set_setting("uuid", uuid)
