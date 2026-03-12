"""
detector.py
===========
Central device detection engine.

Aggregates signals from:
  - MAC OUI lookup
  - DHCP options (Option 55 PRL, Option 60 Vendor Class, hostname)
  - HTTP headers (User-Agent, Server, X-Powered-By)
  - SNMP (sysDescr, sysObjectID, sysName)
  - mDNS / DNS-SD
  - BACnet device info
  - Modbus/TCP presence
  - HL7 MLLP messages
  - Port-based heuristics

Each signal contributes a "confidence weight". The device table is keyed by IP.
Periodically (or on demand) entries are flushed to JSON / CSV / syslog.
"""

import re
import json
import time
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:
    from scripts.oui_lookup import OUILookup
    from data.device_fingerprints import (
        DHCP_FINGERPRINTS, DHCP_VENDOR_CLASS, HTTP_PATTERNS,
        SNMP_PATTERNS, MDNS_PATTERNS, BACNET_VENDOR_IDS,
        KNOWN_PORTS, FIRMWARE_REGEX, KNOWN_ASSETS, KNOWN_SERIAL_NUMBERS
    )
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scripts.oui_lookup import OUILookup
    from data.device_fingerprints import (
        DHCP_FINGERPRINTS, DHCP_VENDOR_CLASS, HTTP_PATTERNS,
        SNMP_PATTERNS, MDNS_PATTERNS, BACNET_VENDOR_IDS,
        KNOWN_PORTS, FIRMWARE_REGEX, KNOWN_ASSETS, KNOWN_SERIAL_NUMBERS
    )

logger = logging.getLogger(__name__)

CONFIDENCE_WEIGHTS = {
    "oui":              20,
    "dhcp_vendor_class":40,
    "dhcp_prl":         25,
    "dhcp_hostname":    30,
    "http_ua":          50,
    "http_server":      45,
    "snmp_sysdescr":    60,
    "snmp_sysoid":      70,
    "mdns":             35,
    "bacnet":           55,
    "modbus_port":      15,
    "hl7":              65,
    "port_heuristic":   10,
    "firmware_string":  30,
}

HIGH_CONFIDENCE_THRESHOLD = 60
MEDIUM_CONFIDENCE_THRESHOLD = 30


@dataclass
class DetectionSignal:
    source: str          # e.g. "dhcp_vendor_class"
    vendor: str
    model: str
    raw_value: str = ""
    firmware: str = ""
    confidence: int = 0  # Computed from CONFIDENCE_WEIGHTS[source]


@dataclass
class DeviceRecord:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    os_hint: str = ""
    device_type: str = ""      # medical / ot / unknown
    confidence: str = "NONE"   # HIGH / MEDIUM / LOW / NONE
    confidence_score: int = 0
    signals: list = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    open_ports: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    notes: str = ""

    def touch(self):
        self.last_seen = time.time()

    def add_signal(self, sig: DetectionSignal):
        self.signals.append(sig)
        self.confidence_score += sig.confidence
        # Update best vendor/model (highest-weight signal wins)
        best = max(self.signals, key=lambda s: s.confidence)
        self.vendor = best.vendor
        self.model = best.model
        if best.firmware:
            self.firmware = best.firmware
        # Update confidence tier
        if self.confidence_score >= HIGH_CONFIDENCE_THRESHOLD:
            self.confidence = "HIGH"
        elif self.confidence_score >= MEDIUM_CONFIDENCE_THRESHOLD:
            self.confidence = "MEDIUM"
        else:
            self.confidence = "LOW"
        # Classify device type
        MEDICAL = {"Alaris","Philips","Hill-Rom","Omnicell","Swisslog","Zoll",
                   "Abbott","Roche","Cadwell","Stryker","GE Healthcare",
                   "Nihon Kohden","Ceribell","Radiometer",
                   "Shimadzu","Siemens Healthineers","Sysmex","Cepheid"}
        OT = {"APC","Eaton","Schneider Electric","Johnson Controls","Beckhoff",
              "Chatsworth Products","Automated Logic","Cooper-Atkins"}
        if any(m in self.vendor for m in MEDICAL):
            self.device_type = "medical"
        elif any(o in self.vendor for o in OT):
            self.device_type = "ot"


class DeviceDetector:
    """
    Thread-safe detection engine.  Feed protocol events via process_* methods.
    """

    def __init__(self, output_file: str = "detected_devices.json",
                 flush_interval: int = 60):
        self._oui = OUILookup()
        self._devices: Dict[str, DeviceRecord] = {}
        self._lock = threading.Lock()
        self._output_file = output_file
        self._flush_interval = flush_interval
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        logger.info("DeviceDetector started. Output → %s", output_file)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _get_or_create(self, ip: str, mac: str = "") -> DeviceRecord:
        if ip not in self._devices:
            self._devices[ip] = DeviceRecord(ip=ip, mac=mac)
            logger.debug("New device: %s / %s", ip, mac)
        dev = self._devices[ip]
        if mac and not dev.mac:
            dev.mac = mac
        self._process_oui(dev)
        dev.touch()
        return dev

    def _process_oui(self, dev: DeviceRecord):
        if not dev.mac:
            return
        result = self._oui.lookup(dev.mac)
        if result["vendor"] != "Unknown":
            sig = DetectionSignal(
                source="oui",
                vendor=result["vendor"],
                model=result.get("notes", ""),
                raw_value=dev.mac,
                confidence=CONFIDENCE_WEIGHTS["oui"],
            )
            dev.add_signal(sig)
            if result.get("notes"):
                dev.notes = result["notes"]

    def _extract_firmware(self, vendor: str, text: str) -> str:
        """Try to pull firmware/version string from arbitrary text."""
        patterns = FIRMWARE_REGEX.get(vendor, [])
        # Also try generic patterns
        patterns += [
            r"(?i)\bfirmware[:\s/]+([A-Za-z0-9\.\-_]+)",
            r"(?i)\bsw[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
            r"(?i)\bv([0-9]+\.[0-9]+\.[0-9]+)",
            r"(?i)\brel[ease]*[:\s]+([A-Za-z0-9\.\-]+)",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group(1) if m.lastindex else m.group(0)
        return ""

    def _match_serial(self, dev: DeviceRecord, text: str):
        """
        Scan arbitrary text for known serial numbers from KNOWN_ASSETS.
        When found, emits a HIGH-confidence signal and annotates the device
        record with owner, location, and asset tag from the registry.
        """
        if not text:
            return
        for serial, asset in KNOWN_ASSETS.items():
            if serial in text:
                sig = DetectionSignal(
                    source="snmp_sysdescr",   # reuse highest weight source
                    vendor=asset["vendor"],
                    model=asset["model"],
                    raw_value="serial={}".format(serial),
                    confidence=CONFIDENCE_WEIGHTS["snmp_sysdescr"],
                )
                dev.add_signal(sig)
                # Annotate with asset registry details
                parts = []
                if asset.get("owner"):
                    parts.append("Owner: {}".format(asset["owner"]))
                if asset.get("location"):
                    parts.append("Location: {}".format(asset["location"]))
                if asset.get("asset_tag"):
                    parts.append("Asset: {}".format(asset["asset_tag"]))
                if parts:
                    dev.notes = "{} | Serial: {}".format(" | ".join(parts), serial)
                logger.info("Serial match: %s → %s %s (%s)",
                            serial, asset["vendor"], asset["model"],
                            asset.get("asset_tag", ""))

    # ------------------------------------------------------------------
    # Public protocol event processors
    # ------------------------------------------------------------------
    def process_dhcp(self, ip: str, mac: str, hostname: str = "",
                     vendor_class: str = "", param_req_list: list = None,
                     dhcp_type: str = ""):
        """
        Call when a DHCP packet is observed.

        :param param_req_list: list of int option numbers from Option 55
        :param vendor_class: string from Option 60
        """
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if hostname:
                dev.hostname = hostname
                # Hostname-based detection
                for keyword, info in DHCP_VENDOR_CLASS.items():
                    if keyword.lower() in hostname.lower():
                        sig = DetectionSignal(
                            source="dhcp_hostname",
                            vendor=info["vendor"],
                            model=info["model"],
                            raw_value=hostname,
                            confidence=CONFIDENCE_WEIGHTS["dhcp_hostname"],
                        )
                        dev.add_signal(sig)
                        break

            if vendor_class:
                for keyword, info in DHCP_VENDOR_CLASS.items():
                    if keyword.lower() in vendor_class.lower():
                        fw = self._extract_firmware(info["vendor"], vendor_class)
                        sig = DetectionSignal(
                            source="dhcp_vendor_class",
                            vendor=info["vendor"],
                            model=info["model"],
                            raw_value=vendor_class,
                            firmware=fw,
                            confidence=CONFIDENCE_WEIGHTS["dhcp_vendor_class"],
                        )
                        dev.add_signal(sig)
                        break

            if param_req_list:
                prl_key = tuple(sorted(param_req_list))
                if prl_key in DHCP_FINGERPRINTS:
                    info = DHCP_FINGERPRINTS[prl_key]
                    sig = DetectionSignal(
                        source="dhcp_prl",
                        vendor=info["vendor"],
                        model=info["model"],
                        raw_value=str(param_req_list),
                        confidence=CONFIDENCE_WEIGHTS["dhcp_prl"],
                    )
                    dev.add_signal(sig)
                else:
                    # Partial match — check subsets
                    prl_set = set(param_req_list)
                    for fp_key, info in DHCP_FINGERPRINTS.items():
                        if prl_set.issuperset(set(fp_key)) and len(fp_key) >= 4:
                            sig = DetectionSignal(
                                source="dhcp_prl",
                                vendor=info["vendor"],
                                model=info["model"] + " (partial PRL match)",
                                raw_value=str(param_req_list),
                                confidence=CONFIDENCE_WEIGHTS["dhcp_prl"] // 2,
                            )
                            dev.add_signal(sig)
                            break

            logger.debug("DHCP processed: %s (%s) → %s %s",
                         ip, mac, dev.vendor, dev.model)
            # Serial number scan across all DHCP text fields
            self._match_serial(dev, " ".join(filter(None, [hostname, vendor_class])))

    def process_http(self, ip: str, mac: str = "", user_agent: str = "",
                     server_header: str = "", uri: str = "",
                     x_powered_by: str = "", response_body_snippet: str = ""):
        """Call for each HTTP request/response observed."""
        with self._lock:
            dev = self._get_or_create(ip, mac)

            checks = [
                ("ua",     user_agent,          "http_ua"),
                ("server", server_header,        "http_server"),
                ("server", x_powered_by,         "http_server"),
                ("ua",     response_body_snippet,"http_ua"),
            ]
            for field_type, text, weight_key in checks:
                if not text:
                    continue
                for pat_info in HTTP_PATTERNS:
                    if pat_info["field"] != field_type:
                        continue
                    if re.search(pat_info["pattern"], text, re.IGNORECASE):
                        fw = self._extract_firmware(pat_info["vendor"], text)
                        sig = DetectionSignal(
                            source=weight_key,
                            vendor=pat_info["vendor"],
                            model=pat_info["model"],
                            raw_value=text[:200],
                            firmware=fw,
                            confidence=CONFIDENCE_WEIGHTS[weight_key],
                        )
                        dev.add_signal(sig)
                        break   # One match per text block is enough
            # Serial number scan across all HTTP text
            all_http_text = " ".join(filter(None, [user_agent, server_header,
                                                    x_powered_by, response_body_snippet]))
            self._match_serial(dev, all_http_text)

    def process_snmp(self, ip: str, mac: str = "", sys_descr: str = "",
                     sys_object_id: str = "", sys_name: str = "",
                     sys_location: str = ""):
        """Call when SNMP GET-RESPONSE data is observed."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if sys_name:
                dev.hostname = dev.hostname or sys_name

            # Match enterprise OID prefix
            if sys_object_id:
                for oid_prefix, info in SNMP_PATTERNS.items():
                    if oid_prefix.startswith("sysDescr:"):
                        continue
                    if sys_object_id.startswith(oid_prefix):
                        fw = self._extract_firmware(info["vendor"], sys_descr)
                        sig = DetectionSignal(
                            source="snmp_sysoid",
                            vendor=info["vendor"],
                            model=info["model"],
                            raw_value=sys_object_id,
                            firmware=fw,
                            confidence=CONFIDENCE_WEIGHTS["snmp_sysoid"],
                        )
                        dev.add_signal(sig)
                        break

            # Match sysDescr substrings
            if sys_descr:
                for key, info in SNMP_PATTERNS.items():
                    if not key.startswith("sysDescr:"):
                        continue
                    keyword = key.split(":", 1)[1]
                    if keyword.lower() in sys_descr.lower():
                        fw = self._extract_firmware(info["vendor"], sys_descr)
                        sig = DetectionSignal(
                            source="snmp_sysdescr",
                            vendor=info["vendor"],
                            model=info["model"],
                            raw_value=sys_descr[:300],
                            firmware=fw,
                            confidence=CONFIDENCE_WEIGHTS["snmp_sysdescr"],
                        )
                        dev.add_signal(sig)
                        break
            # Serial number scan across all SNMP text fields
            self._match_serial(dev, " ".join(filter(None,
                [sys_descr, sys_name, sys_location])))

    def process_mdns(self, ip: str, mac: str = "", service_name: str = "",
                     service_type: str = "", txt_records: dict = None):
        """Call for each mDNS / DNS-SD record observed."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            combined = " ".join(filter(None, [service_name, service_type,
                                              str(txt_records or "")]))
            for pat_info in MDNS_PATTERNS:
                if re.search(pat_info["pattern"], combined, re.IGNORECASE):
                    fw = ""
                    if txt_records:
                        fw = (txt_records.get("firmware") or
                              txt_records.get("version") or
                              txt_records.get("sw") or "")
                    sig = DetectionSignal(
                        source="mdns",
                        vendor=pat_info["vendor"],
                        model=pat_info["model"],
                        raw_value=combined[:200],
                        firmware=fw,
                        confidence=CONFIDENCE_WEIGHTS["mdns"],
                    )
                    dev.add_signal(sig)
                    break

    def process_bacnet(self, ip: str, mac: str = "", vendor_id: int = None,
                       object_name: str = "", model_name: str = "",
                       application_sw_version: str = "",
                       firmware_revision: str = ""):
        """Call when a BACnet I-Am or ReadProperty response is observed."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if not "bacnet" in dev.protocols:
                dev.protocols.append("bacnet")
            vendor = "Unknown BACnet"
            model = model_name or object_name or "BACnet Device"
            if vendor_id and vendor_id in BACNET_VENDOR_IDS:
                info = BACNET_VENDOR_IDS[vendor_id]
                vendor = info["vendor"]
                model = model_name or info["model"]
            fw = firmware_revision or application_sw_version
            sig = DetectionSignal(
                source="bacnet",
                vendor=vendor,
                model=model,
                raw_value=f"vendor_id={vendor_id} obj={object_name}",
                firmware=fw,
                confidence=CONFIDENCE_WEIGHTS["bacnet"],
            )
            dev.add_signal(sig)

    def process_modbus(self, ip: str, mac: str = "", unit_id: int = 1,
                       device_id_str: str = ""):
        """Call when Modbus TCP traffic (port 502) is observed."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if "modbus" not in dev.protocols:
                dev.protocols.append("modbus")
            vendor = dev.vendor or "Unknown Modbus"
            model = device_id_str or dev.model or "Modbus Device"
            sig = DetectionSignal(
                source="modbus_port",
                vendor=vendor,
                model=model,
                raw_value=f"unit_id={unit_id} {device_id_str}",
                confidence=CONFIDENCE_WEIGHTS["modbus_port"],
            )
            dev.add_signal(sig)

    def process_hl7(self, ip: str, mac: str = "", msh_segment: str = "",
                    sending_application: str = "", sending_facility: str = ""):
        """Call when HL7 MLLP traffic is observed (port 2575)."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if "hl7" not in dev.protocols:
                dev.protocols.append("hl7")

            try:
                from data.device_fingerprints import HL7_PATTERNS
            except ImportError:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from data.device_fingerprints import HL7_PATTERNS

            combined = " ".join(filter(None, [msh_segment, sending_application,
                                              sending_facility]))
            for pat_info in HL7_PATTERNS:
                if re.search(pat_info["pattern"], combined, re.IGNORECASE):
                    sig = DetectionSignal(
                        source="hl7",
                        vendor=pat_info["vendor"],
                        model=pat_info["model"],
                        raw_value=combined[:200],
                        confidence=CONFIDENCE_WEIGHTS["hl7"],
                    )
                    dev.add_signal(sig)
                    break

    def process_port_observation(self, ip: str, mac: str = "",
                                 port: int = 0, protocol: str = "tcp"):
        """Call whenever a new open port/protocol is observed for a host."""
        with self._lock:
            dev = self._get_or_create(ip, mac)
            if port not in dev.open_ports:
                dev.open_ports.append(port)
            if port in KNOWN_PORTS:
                for info in KNOWN_PORTS[port]:
                    if info["proto"] not in dev.protocols:
                        dev.protocols.append(info["proto"])
                    # Only add low-weight signal if vendor still unknown
                    if dev.confidence_score < MEDIUM_CONFIDENCE_THRESHOLD:
                        sig = DetectionSignal(
                            source="port_heuristic",
                            vendor=info["vendor"],
                            model=info["proto"],
                            raw_value=f"port={port}/{protocol}",
                            confidence=CONFIDENCE_WEIGHTS["port_heuristic"],
                        )
                        dev.add_signal(sig)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def get_devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for dev in self._devices.values():
                d = asdict(dev)
                # Serialize signals to cleaner dicts
                d["signals"] = [asdict(s) for s in dev.signals]
                d["first_seen"] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(dev.first_seen))
                d["last_seen"] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(dev.last_seen))
                out.append(d)
            return sorted(out, key=lambda x: x["confidence_score"], reverse=True)

    def flush(self):
        devices = self.get_devices()
        try:
            with open(self._output_file, "w") as fh:
                json.dump(devices, fh, indent=2, default=str)
            logger.info("Flushed %d devices → %s", len(devices), self._output_file)
        except IOError as e:
            logger.error("Flush failed: %s", e)

    def _flush_loop(self):
        while True:
            time.sleep(self._flush_interval)
            self.flush()

    def print_summary(self):
        devices = self.get_devices()
        print(f"\n{'='*80}")
        print(f"  DETECTED DEVICES  ({len(devices)} total)")
        print(f"{'='*80}")
        fmt = "{:<18} {:<17} {:<22} {:<30} {:<15} {:<8} {:<6}"
        print(fmt.format("IP", "MAC", "Vendor", "Model",
                         "Firmware", "Type", "Conf"))
        print("-" * 116)
        for d in devices:
            print(fmt.format(
                d["ip"][:17],
                d["mac"][:16],
                d["vendor"][:21],
                d["model"][:29],
                (d["firmware"] or "-")[:14],
                d["device_type"][:7],
                d["confidence"][:5],
            ))
        print()
