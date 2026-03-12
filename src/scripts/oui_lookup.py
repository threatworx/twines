"""
oui_lookup.py
=============
MAC address OUI resolution with multi-tier lookups:
  1. Local curated database (device_fingerprints.py) - most specific
  2. Bundled IEEE OUI flat file (ieee_oui.txt) if present
  3. Manuf file from Wireshark (manuf) if present

Usage:
    from scripts.oui_lookup import OUILookup
    lu = OUILookup()
    result = lu.lookup("00:02:A5:11:22:33")
    # → {"mac": "00:02:A5:11:22:33", "oui": "00:02:A5",
    #    "vendor": "Philips", "source": "local_db", "notes": "..."}
"""

import re
import os
import logging
from functools import lru_cache
from typing import Dict, List, Optional
from mac_vendor_lookup import MacLookup

# Adjust import path when used standalone vs as part of package
try:
    from data.device_fingerprints import OUI_MAP
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from data.device_fingerprints import OUI_MAP

logger = logging.getLogger(__name__)

# Possible locations for the Wireshark manuf file
MANUF_PATHS = [
    "/usr/share/wireshark/manuf",
    "/usr/share/wireshark/manuf.gz",
    "/opt/homebrew/share/wireshark/manuf",
    "/usr/local/share/wireshark/manuf",
    os.path.join(os.path.dirname(__file__), "..", "data", "manuf"),
]

IEEE_OUI_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "data", "ieee_oui.txt"),
    "/usr/share/nmap/nmap-mac-prefixes",
]


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated (XX:XX:XX:XX:XX:XX)."""
    mac = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(mac) < 6:
        raise ValueError(f"Invalid MAC: {mac!r}")
    return ":".join(mac[i:i+2].upper() for i in range(0, min(12, len(mac)), 2))


def _oui_from_mac(mac_norm: str) -> str:
    """Return the 24-bit OUI prefix (first 3 octets) from a normalized MAC."""
    return ":".join(mac_norm.split(":")[:3])


class OUILookup:
    """Multi-source OUI resolver."""

    def __init__(self):
        self._manuf: Dict[str, str] = {}
        self._ieee: Dict[str, str] = {}
        self._load_manuf()
        self._load_ieee()
        self._pyouilookup = MacLookup()

    # ------------------------------------------------------------------
    def _load_manuf(self):
        """Load Wireshark manuf file if available."""
        for path in MANUF_PATHS:
            if not os.path.isfile(path):
                continue
            try:
                import gzip
                opener = gzip.open if path.endswith(".gz") else open
                with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t", 2)
                        if len(parts) < 2:
                            continue
                        prefix = parts[0].strip().upper().replace("-", ":")
                        name = parts[-1].strip() if len(parts) == 3 else parts[1].strip()
                        self._manuf[prefix] = name
                logger.debug("Loaded %d entries from manuf: %s", len(self._manuf), path)
                return
            except Exception as exc:
                logger.warning("Could not load manuf %s: %s", path, exc)

    def _load_ieee(self):
        """Load IEEE OUI flat file if available."""
        for path in IEEE_OUI_PATHS:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        # Format: AABBCC  Vendor Name
                        m = re.match(r"^([0-9A-Fa-f]{6})\s+(.*)", line.strip())
                        if m:
                            hex_oui = m.group(1).upper()
                            oui = ":".join(hex_oui[i:i+2] for i in range(0, 6, 2))
                            self._ieee[oui] = m.group(2).strip()
                logger.debug("Loaded %d entries from IEEE OUI: %s", len(self._ieee), path)
                return
            except Exception as exc:
                logger.warning("Could not load IEEE OUI %s: %s", path, exc)

    # ------------------------------------------------------------------
    @lru_cache(maxsize=4096)
    def lookup(self, mac: str) -> dict:
        """
        Resolve a MAC address to vendor information.

        Returns dict with keys:
          mac, oui, vendor, model (optional), notes (optional),
          confidence, source
        """
        try:
            mac_norm = _normalize_mac(mac)
        except ValueError:
            return {"mac": mac, "vendor": "Unknown", "confidence": "NONE",
                    "source": "error", "error": "Invalid MAC"}

        oui = _oui_from_mac(mac_norm)

        # 0 - Use ouilookup python module
        v = self._pyouilookup.lookup(oui)
        if v:
            return {
                "mac": mac_norm,
                "oui": oui,
                "vendor": v,
                "notes": "",
                "confidence": "MEDIUM",
                "source": "ouilookup",
            }

        # 1 — Local curated DB (highest priority)
        if oui in OUI_MAP:
            entry = OUI_MAP[oui]
            return {
                "mac": mac_norm,
                "oui": oui,
                "vendor": entry["vendor"],
                "notes": entry.get("notes", ""),
                "confidence": "MEDIUM",   # OUI alone = MEDIUM; caller upgrades with other signals
                "source": "local_db",
            }

        # 2 — Wireshark manuf
        if oui in self._manuf:
            return {
                "mac": mac_norm,
                "oui": oui,
                "vendor": self._manuf[oui],
                "confidence": "LOW",
                "source": "manuf",
            }

        # 3 — IEEE OUI file
        logger.info("Looking up OUI from IEEE file")
        if oui in self._ieee:
            return {
                "mac": mac_norm,
                "oui": oui,
                "vendor": self._ieee[oui],
                "confidence": "LOW",
                "source": "ieee_oui",
            }

        return {
            "mac": mac_norm,
            "oui": oui,
            "vendor": "Unknown",
            "confidence": "NONE",
            "source": "none",
        }



    def is_medical_vendor(self, mac: str) -> bool:
        """Quick check: does this MAC belong to a known medical device vendor?"""
        MEDICAL_VENDORS = {
            "Alaris", "Alaris/BD", "Philips", "Hill-Rom", "Omnicell",
            "Swisslog", "Zoll", "Abbott", "Roche", "Cadwell", "Stryker",
            "GE Healthcare", "Nihon Kohden", "Ceribell", "Radiometer",
        }
        r = self.lookup(mac)
        return any(mv in r.get("vendor", "") for mv in MEDICAL_VENDORS)

    def is_ot_vendor(self, mac: str) -> bool:
        """Quick check: does this MAC belong to a known OT device vendor?"""
        OT_VENDORS = {
            "APC", "Eaton", "Schneider Electric", "Johnson Controls",
            "Beckhoff", "Chatsworth Products", "Automated Logic",
            "Cooper-Atkins",
        }
        r = self.lookup(mac)
        return any(ov in r.get("vendor", "") for ov in OT_VENDORS)


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json, sys
    lu = OUILookup()
    for mac in sys.argv[1:]:
        print(json.dumps(lu.lookup(mac), indent=2))
