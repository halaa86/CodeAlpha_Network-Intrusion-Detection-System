import json
from pathlib import Path
from typing import Iterator, Dict, Any

class AlertParser:
    def __init__(self, eve_log_path: str):
        self.eve_log_path = Path(eve_log_path)

    def read_existing(self) -> Iterator[Dict[str, Any]]:
        """Yield all alerts currently in the file."""
        if not self.eve_log_path.exists():
            return
        with self.eve_log_path.open() as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    yield self._normalize(event)

    def tail(self) -> Iterator[Dict[str, Any]]:
        """Follow the log file and yield new alerts as they appear."""
        import time
        if not self.eve_log_path.exists():
            raise FileNotFoundError(f"Eve log not found: {self.eve_log_path}")

        with self.eve_log_path.open() as f:
            f.seek(0, 2)  # go to end
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    yield self._normalize(event)

    @staticmethod
    def _normalize(event: Dict[str, Any]) -> Dict[str, Any]:
        alert = event.get("alert", {})
        return {
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dest_ip": event.get("dest_ip"),
            "dest_port": event.get("dest_port"),
            "proto": event.get("proto"),
            "signature": alert.get("signature"),
            "signature_id": alert.get("signature_id"),
            "severity": alert.get("severity"),
            "category": alert.get("category"),
        }
