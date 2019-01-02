from .config import ICSConfig

import os

ROOT_PATH = os.getcwd()
CONFIG_PATH = os.path.join(ROOT_PATH, 'ics.ini')

config = ICSConfig(config_path=CONFIG_PATH)
