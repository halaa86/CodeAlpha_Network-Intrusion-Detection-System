import yaml
from pathlib import Path

def load_config(path: str = "config/settings.yaml") -> dict:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with config_path.open() as f:
        return yaml.safe_load(f)
