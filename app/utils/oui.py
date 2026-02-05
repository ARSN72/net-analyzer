import csv
import os
from typing import Dict, Tuple


class OUILookup:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.oui_map: Dict[str, Tuple[str, str]] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.csv_path):
            return
        with open(self.csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                prefix = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                addr = (row.get("Organization Address") or "").strip()
                if prefix:
                    self.oui_map[prefix] = (org or "Unknown", addr or "Unknown")

    def lookup(self, mac: str) -> dict:
        norm = self._normalize_mac(mac)
        if not norm:
            return {
                "mac_vendor": "Unknown",
                "manufacturer": "Unknown",
                "manufacturer_address": "Unknown",
                "vendor_source": "IEEE OUI",
                "vendor_confidence": 0.0,
            }

        if norm == "FFFFFFFFFFFF":
            return {
                "mac_vendor": "Broadcast",
                "manufacturer": "Broadcast",
                "manufacturer_address": "Unknown",
                "vendor_source": "Local",
                "vendor_confidence": 1.0,
            }

        if self._is_locally_administered(norm):
            return {
                "mac_vendor": "Locally Administered",
                "manufacturer": "Locally Administered",
                "manufacturer_address": "Unknown",
                "vendor_source": "Local",
                "vendor_confidence": 1.0,
            }

        prefix = norm[:6]
        if prefix in self.oui_map:
            org, addr = self.oui_map[prefix]
            return {
                "mac_vendor": org,
                "manufacturer": org,
                "manufacturer_address": addr,
                "vendor_source": "IEEE OUI",
                "vendor_confidence": 1.0,
            }

        return {
            "mac_vendor": "Unknown",
            "manufacturer": "Unknown",
            "manufacturer_address": "Unknown",
            "vendor_source": "IEEE OUI",
            "vendor_confidence": 0.0,
        }

    def _normalize_mac(self, mac: str) -> str:
        if not mac:
            return ""
        cleaned = mac.replace(":", "").replace("-", "").strip().upper()
        if len(cleaned) < 12:
            return ""
        return cleaned[:12]

    def _is_locally_administered(self, mac_norm: str) -> bool:
        try:
            first_octet = int(mac_norm[:2], 16)
            return bool(first_octet & 0x02)
        except ValueError:
            return False
