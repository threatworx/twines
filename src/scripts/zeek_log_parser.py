"""
zeek_log_parser.py
==================
Reads Zeek TSV log files (both live rotation and historical) and feeds events
to the DeviceDetector.

Supports all relevant Zeek logs:
  - conn.log        → port observations, MAC via ARP correlation
  - dhcp.log        → DHCP fingerprinting (hostname, vendor class, PRL)
  - http.log        → User-Agent, Server headers
  - dns.log         → mDNS (src port 5353), hostname correlation
  - snmp.log        → sysDescr (requires Zeek SNMP policy script)
  - bacnet.log      → BACnet (requires Zeek bacnet package)
  - modbus.log      → Modbus TCP (requires Zeek modbus package)
  - arp.log         → IP→MAC mapping (requires Zeek arp package)
  - ssl.log         → TLS CN / SAN hostname hints
  - weird.log       → unusual protocol activity as context

Live mode: tails files in a directory and feeds events as they arrive.
Batch mode: processes files top-to-bottom.

Usage:
    python zeek_log_parser.py --log-dir /opt/zeek/logs/current --live
    python zeek_log_parser.py --log-dir /opt/zeek/logs/2024-01-15 --batch
"""

import os
import re
import sys
import time
import glob
import json
import logging
import argparse
import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

try:
    from scripts.detector import DeviceDetector
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scripts.detector import DeviceDetector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Zeek TSV log reader
# ---------------------------------------------------------------------------
class ZeekLogReader:
    """
    Reads a Zeek TSV log file, handles the #fields / #types header,
    yields dicts of {field: value} for each data row.
    """

    def __init__(self, path: str):
        self.path = path
        self._fields: List[str] = []
        self._types: List[str] = []
        self._separator = "\t"
        self._unset_field = "-"
        self._empty_field = "(empty)"

    def _parse_header(self, line: str):
        line = line.rstrip("\n")
        if line.startswith("#separator"):
            sep_hex = line.split()[-1]
            try:
                self._separator = bytes.fromhex(sep_hex.replace("\\x", "")).decode()
            except Exception:
                self._separator = "\t"
        elif line.startswith("#fields"):
            self._fields = line.split(self._separator)[1:]
        elif line.startswith("#types"):
            self._types = line.split(self._separator)[1:]
        elif line.startswith("#unset_field"):
            self._unset_field = line.split(self._separator, 1)[-1].strip()
        elif line.startswith("#empty_field"):
            self._empty_field = line.split(self._separator, 1)[-1].strip()

    def _parse_row(self, line: str) -> Optional[dict]:
        if line.startswith("#") or not line.strip():
            return None
        parts = line.rstrip("\n").split(self._separator)
        if not self._fields:
            return None
        row = {}
        for i, f in enumerate(self._fields):
            val = parts[i] if i < len(parts) else self._unset_field
            if val == self._unset_field:
                val = None
            elif val == self._empty_field:
                val = ""
            row[f] = val
        return row

    def read(self):
        """Generator: yields dicts for each data row."""
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#"):
                        self._parse_header(line)
                    else:
                        row = self._parse_row(line)
                        if row:
                            yield row
        except FileNotFoundError:
            logger.warning("Log file not found: %s", self.path)
        except PermissionError:
            logger.warning("Cannot read: %s", self.path)

    def tail(self, callback: Callable, poll_interval: float = 0.5):
        """
        Tail the log file continuously, calling callback(row) for new rows.
        Handles file rotation by detecting inode changes.
        """
        inode = None
        position = 0
        try:
            stat = os.stat(self.path)
            inode = stat.st_ino
        except FileNotFoundError:
            pass

        while True:
            try:
                stat = os.stat(self.path)
                if inode != stat.st_ino:
                    # File rotated
                    position = 0
                    inode = stat.st_ino
                    self._fields = []
                    self._types = []

                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(position)
                    for line in fh:
                        if line.startswith("#"):
                            self._parse_header(line)
                        else:
                            row = self._parse_row(line)
                            if row:
                                callback(row)
                    position = fh.tell()
            except FileNotFoundError:
                time.sleep(1)
            except Exception as e:
                logger.error("Tail error on %s: %s", self.path, e)
            time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Per-log-type event handlers
# ---------------------------------------------------------------------------
class ZeekEventProcessor:
    """
    Translates Zeek log rows into DeviceDetector events.
    """

    def __init__(self, detector: DeviceDetector):
        self.det = detector
        # IP → MAC mapping built from ARP / DHCP logs
        self._arp_table: Dict[str, str] = {}
        self._lock = threading.Lock()

    def _mac_for_ip(self, ip: str, mac_from_log: str = "") -> str:
        if mac_from_log and mac_from_log != "-":
            return mac_from_log
        with self._lock:
            return self._arp_table.get(ip, "")

    def _learn_mac(self, ip: str, mac: str):
        if ip and mac and mac != "-":
            with self._lock:
                self._arp_table[ip] = mac

    # ------------------------------------------------------------------
    def on_dhcp(self, row: dict):
        """Handle dhcp.log row."""
        ip = row.get("assigned_addr") or row.get("client_addr") or ""
        mac = row.get("mac") or ""
        hostname = row.get("host_name") or ""
        vendor_class = row.get("client_software") or row.get("vendor_class") or ""
        requested_addr = row.get("requested_addr") or ""
        msg_types = row.get("msg_types") or ""

        # Option 55 PRL is not default in dhcp.log; check for it
        prl_raw = row.get("client_software") or ""   # Some custom Zeek builds expose it
        # Parse PRL if present as comma-separated ints
        prl = []
        if prl_raw and re.match(r"^[\d,\s]+$", prl_raw):
            prl = [int(x) for x in re.split(r"[,\s]+", prl_raw) if x.strip().isdigit()]

        if ip and mac:
            self._learn_mac(ip, mac)

        if ip:
            self.det.process_dhcp(
                ip=ip, mac=mac, hostname=hostname,
                vendor_class=vendor_class, param_req_list=prl
            )

    def on_http(self, row: dict):
        """Handle http.log row."""
        ip = row.get("id.orig_h") or ""
        dst_ip = row.get("id.resp_h") or ""
        mac = self._mac_for_ip(ip)
        ua = row.get("user_agent") or ""
        server = row.get("server") or ""
        uri = row.get("uri") or ""
        # Prefer server-side detection for medical device HTTP servers
        # (they expose server banners, not user-agents)
        if dst_ip:
            dst_mac = self._mac_for_ip(dst_ip)
            self.det.process_http(ip=dst_ip, mac=dst_mac,
                                  user_agent="", server_header=server, uri=uri)
        if ip and ua:
            self.det.process_http(ip=ip, mac=mac, user_agent=ua,
                                  server_header="", uri=uri)

    def on_dns(self, row: dict):
        """Handle dns.log row — look for mDNS (port 5353) service records."""
        src_port = row.get("id.orig_p") or ""
        dst_port = row.get("id.resp_p") or ""
        ip = row.get("id.orig_h") or ""
        mac = self._mac_for_ip(ip)
        query = row.get("query") or ""
        answers = row.get("answers") or ""

        # mDNS
        if dst_port == "5353" or src_port == "5353":
            combined = f"{query} {answers}"
            if combined.strip():
                self.det.process_mdns(ip=ip, mac=mac,
                                      service_name=query,
                                      service_type=answers)

        # PTR records can reveal hostname → correlate
        if row.get("qtype_name") == "PTR" and answers:
            hostname = answers.split(",")[0].strip().rstrip(".")
            if hostname and ip:
                with self._lock:
                    # Already have MAC for this IP, update hostname
                    pass  # detector handles hostname in DHCP; no action needed here

    def on_snmp(self, row: dict):
        """Handle snmp.log row (requires Zeek SNMP policy script)."""
        ip = row.get("id.resp_h") or row.get("id.orig_h") or ""
        mac = self._mac_for_ip(ip)
        # Zeek snmp.log columns vary by version; try common field names
        community = row.get("community") or ""
        get_requests = row.get("get_requests") or ""
        get_bulk = row.get("get_bulk_requests") or ""
        set_requests = row.get("set_requests") or ""
        display_string = row.get("display_string") or ""  # sysDescr if captured
        oid = row.get("oid") or ""

        if display_string:
            self.det.process_snmp(ip=ip, mac=mac,
                                  sys_descr=display_string,
                                  sys_object_id=oid)
        elif oid:
            self.det.process_snmp(ip=ip, mac=mac, sys_object_id=oid)

    def on_conn(self, row: dict):
        """Handle conn.log row — extract open ports."""
        src_ip = row.get("id.orig_h") or ""
        dst_ip = row.get("id.resp_h") or ""
        mac = row.get("resp_l2_addr") or ""
        dst_port_s = row.get("id.resp_p") or "0"
        proto = row.get("proto") or "tcp"
        history = row.get("history") or ""
        conn_state = row.get("conn_state") or ""

        try:
            dst_port = int(dst_port_s)
        except ValueError:
            return

        # Only consider established connections (not resets / refused)
        if conn_state in ("SF", "S1", "RSTO", "RSTR", "OTH"):
            #mac = self._mac_for_ip(dst_ip)
            self.det.process_port_observation(ip=dst_ip, mac=mac,
                                              port=dst_port, protocol=proto)

    def on_arp(self, row: dict):
        """Handle arp.log row (requires Zeek arp package)."""
        src_ip = row.get("src_ip") or row.get("srca") or ""
        src_mac = row.get("src_mac") or row.get("srcmac") or ""
        dst_ip = row.get("dst_ip") or ""
        # IS-AT replies contain the MAC of the responding device
        operation = row.get("operation") or row.get("op") or ""
        if src_ip and src_mac:
            self._learn_mac(src_ip, src_mac)
            # Trigger OUI processing via a lightweight port event
            mac = self._mac_for_ip(src_ip, src_mac)
            self.det.process_port_observation(ip=src_ip, mac=mac, port=0)

    def on_bacnet(self, row: dict):
        """Handle bacnet.log (requires Zeek bacnet package)."""
        ip = row.get("id.orig_h") or row.get("id.resp_h") or ""
        mac = self._mac_for_ip(ip)
        vendor_id_s = row.get("vendor_id") or "0"
        try:
            vendor_id = int(vendor_id_s)
        except ValueError:
            vendor_id = 0
        object_name = row.get("object_name") or ""
        model_name = row.get("model_name") or ""
        app_sw = row.get("application_software_revision") or ""
        fw = row.get("firmware_revision") or ""

        self.det.process_bacnet(ip=ip, mac=mac, vendor_id=vendor_id,
                                object_name=object_name, model_name=model_name,
                                application_sw_version=app_sw,
                                firmware_revision=fw)

    def on_modbus(self, row: dict):
        """Handle modbus.log (requires Zeek modbus package)."""
        ip = row.get("id.orig_h") or row.get("id.resp_h") or ""
        mac = self._mac_for_ip(ip)
        unit_id_s = row.get("unit_id") or "1"
        try:
            unit_id = int(unit_id_s)
        except ValueError:
            unit_id = 1
        func = row.get("func") or ""
        exception = row.get("exception") or ""
        self.det.process_modbus(ip=ip, mac=mac, unit_id=unit_id,
                                device_id_str=func)

    def on_ssl(self, row: dict):
        """Handle ssl.log — extract CN / SAN for hostname hints."""
        ip = row.get("id.resp_h") or ""
        mac = self._mac_for_ip(ip)
        cn = row.get("subject") or ""
        san = row.get("san.dns") or ""
        combined = f"{cn} {san}"
        # Reuse HTTP patterns against TLS certificate CN
        if combined.strip():
            self.det.process_http(ip=ip, mac=mac,
                                  user_agent=combined,
                                  server_header=combined)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
LOG_HANDLERS = {
    "dhcp":    "on_dhcp",
    "http":    "on_http",
    "dns":     "on_dns",
    "snmp":    "on_snmp",
    "conn":    "on_conn",
    "arp":     "on_arp",
    "bacnet":  "on_bacnet",
    "modbus":  "on_modbus",
    "ssl":     "on_ssl",
}


class ZeekLogOrchestrator:
    """
    Manages file discovery and routing for a Zeek log directory.
    """

    def __init__(self, log_dir: str, detector: DeviceDetector,
                 live: bool = False):
        self.log_dir = log_dir
        self.detector = detector
        self.processor = ZeekEventProcessor(detector)
        self.live = live

    def _log_path(self, name: str) -> str:
        # Support both current/ style (no extension) and compressed
        for ext in ["", ".log", ".log.gz"]:
            p = os.path.join(self.log_dir, f"{name}{ext}")
            if os.path.exists(p):
                return p
        return os.path.join(self.log_dir, f"{name}.log")

    def process_batch(self):
        """Process all known log files once (historical analysis)."""
        for log_name, handler_name in LOG_HANDLERS.items():
            path = self._log_path(log_name)
            handler = getattr(self.processor, handler_name)
            reader = ZeekLogReader(path)
            count = 0
            for row in reader.read():
                try:
                    handler(row)
                    count += 1
                except Exception as e:
                    logger.debug("Handler error for %s row: %s", log_name, e)
            if count:
                logger.info("Processed %d rows from %s", count, path)

        self.detector.flush()
        self.detector.print_summary()

    def process_live(self):
        """Continuously tail all known log files in separate threads."""
        threads = []
        for log_name, handler_name in LOG_HANDLERS.items():
            path = self._log_path(log_name)
            handler = getattr(self.processor, handler_name)
            reader = ZeekLogReader(path)

            def make_callback(h):
                def cb(row):
                    try:
                        h(row)
                    except Exception as e:
                        logger.debug("Live handler error: %s", e)
                return cb

            t = threading.Thread(
                target=reader.tail,
                args=(make_callback(handler),),
                name=f"tail-{log_name}",
                daemon=True,
            )
            t.start()
            threads.append(t)
            logger.info("Tailing %s", path)

        # Main thread: periodic summary print
        try:
            while True:
                time.sleep(30)
                self.detector.print_summary()
        except KeyboardInterrupt:
            self.detector.flush()
            logger.info("Stopped.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Zeek device detector log parser")
    parser.add_argument("--log-dir", default="/opt/zeek/logs/current",
                        help="Zeek log directory")
    parser.add_argument("--live", action="store_true",
                        help="Tail logs in real-time (default: batch mode)")
    parser.add_argument("--output", default="detected_devices.json",
                        help="Output JSON file")
    parser.add_argument("--flush-interval", type=int, default=60,
                        help="Seconds between JSON flushes (live mode)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    detector = DeviceDetector(output_file=args.output,
                              flush_interval=args.flush_interval)
    orch = ZeekLogOrchestrator(log_dir=args.log_dir,
                               detector=detector,
                               live=args.live)

    if args.live:
        logger.info("Starting live mode on %s", args.log_dir)
        orch.process_live()
    else:
        logger.info("Batch processing %s", args.log_dir)
        orch.process_batch()


if __name__ == "__main__":
    main()
