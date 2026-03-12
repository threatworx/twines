"""
active_prober.py
================
OPTIONAL active probing module.
Sends targeted, low-impact queries to devices already identified passively
to enrich firmware/version data.

⚠️  IMPORTANT: Active probing is NOT fully passive. Only use this module
    if you have explicit authorization. All probes are read-only.

Supported protocols:
  - SNMP v1/v2c GET (sysDescr, sysObjectID, sysName, sysLocation,
                     hrSWInstalledName, entPhysicalFirmwareRev)
  - BACnet ReadProperty (vendor, model, app-sw-version, firmware)
  - HTTP HEAD / GET on known paths (/version, /api/v1/info, etc.)
  - Modbus FC43 (Device Identification, MEI type 14)

Usage:
    prober = ActiveProber(community="public", timeout=2)
    result = prober.probe_snmp("192.168.1.100")
    result = prober.probe_http("192.168.1.101")
"""

import re
import json
import socket
import struct
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SNMP v2c prober (pure Python, no pysnmp dependency)
# ---------------------------------------------------------------------------

def _encode_oid(oid_str: str) -> bytes:
    """Encode dotted OID string to BER bytes."""
    parts = [int(x) for x in oid_str.lstrip(".").split(".")]
    # First two components are encoded as 40*first + second
    encoded = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
        else:
            sub = []
            while part:
                sub.append(part & 0x7F)
                part >>= 7
            sub.reverse()
            for i, b in enumerate(sub):
                encoded.append(b | (0x80 if i < len(sub) - 1 else 0))
    return bytes([0x06, len(encoded)] + encoded)


def _snmp_get_request(community: str, oid: str, request_id: int = 1) -> bytes:
    """Build a minimal SNMPv2c GET request PDU."""
    oid_bytes = _encode_oid(oid)
    # VarBind: SEQUENCE { OID, NULL }
    varbind = bytes([0x30, len(oid_bytes) + 2]) + oid_bytes + bytes([0x05, 0x00])
    # VarBindList
    varbindlist = bytes([0x30, len(varbind)]) + varbind
    # GetRequest PDU (tag 0xA0)
    req_id_bytes = struct.pack(">I", request_id & 0x7FFFFFFF)
    req_id_ber = bytes([0x02, 0x04]) + req_id_bytes
    error_status = bytes([0x02, 0x01, 0x00])
    error_index  = bytes([0x02, 0x01, 0x00])
    pdu_content = req_id_ber + error_status + error_index + varbindlist
    pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
    # Community string
    comm_bytes = community.encode("ascii")
    comm_ber = bytes([0x04, len(comm_bytes)]) + comm_bytes
    # Version (v2c = 1)
    version_ber = bytes([0x02, 0x01, 0x01])
    msg_content = version_ber + comm_ber + pdu
    return bytes([0x30, len(msg_content)]) + msg_content


def _parse_snmp_string(response: bytes) -> Optional[str]:
    """
    Very simple BER parser: scan response bytes for the first OCTET STRING (0x04)
    that is longer than 4 bytes and return it as UTF-8.
    """
    i = 0
    while i < len(response) - 2:
        tag = response[i]
        length = response[i + 1]
        if length & 0x80:
            # Multi-byte length
            num_bytes = length & 0x7F
            if i + 1 + num_bytes >= len(response):
                break
            length = int.from_bytes(response[i+2:i+2+num_bytes], "big")
            i += num_bytes
        value_start = i + 2
        value_end = value_start + length
        if tag == 0x04 and length > 4 and value_end <= len(response):
            try:
                return response[value_start:value_end].decode("utf-8", errors="replace").strip()
            except Exception:
                pass
        i += 2 + length
    return None


class ActiveProber:
    SNMP_OIDs = {
        "sysDescr":     "1.3.6.1.2.1.1.1.0",
        "sysObjectID":  "1.3.6.1.2.1.1.2.0",
        "sysName":      "1.3.6.1.2.1.1.5.0",
        "sysLocation":  "1.3.6.1.2.1.1.6.0",
        # ENTITY-MIB firmware revision
        "entFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9.1",
        # HOST-RESOURCES-MIB installed SW
        "hrSWInstalledName": "1.3.6.1.2.1.25.6.3.1.2.1",
        # APC-specific: AOS firmware
        "apcSWVersion":  "1.3.6.1.4.1.318.1.1.1.1.2.1.0",
        # Eaton UPS firmware
        "eatonFirmware": "1.3.6.1.4.1.534.1.1.2.0",
    }

    # HTTP paths that may reveal version/model info
    HTTP_PATHS = [
        "/",
        "/version",
        "/api/version",
        "/api/v1/info",
        "/api/v1/version",
        "/cgi-bin/version",
        "/rest/system",
        "/manage/summary",
        "/system/info",
        "/status",
        "/index.html",
    ]

    def __init__(self, community: str = "public", timeout: float = 2.0,
                 snmp_port: int = 161):
        self.community = community
        self.timeout = timeout
        self.snmp_port = snmp_port

    def probe_snmp(self, ip: str) -> dict:
        """
        Send SNMP GET for key OIDs. Returns dict of {oid_name: value}.
        """
        results = {}
        for name, oid in self.SNMP_OIDs.items():
            try:
                pkt = _snmp_get_request(self.community, oid, request_id=hash(oid) & 0xFFFF)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(pkt, (ip, self.snmp_port))
                    try:
                        data, _ = sock.recvfrom(4096)
                        value = _parse_snmp_string(data)
                        if value:
                            results[name] = value
                            logger.debug("SNMP %s %s → %s", ip, name, value[:60])
                    except socket.timeout:
                        pass
            except Exception as e:
                logger.debug("SNMP probe error %s %s: %s", ip, oid, e)
        return results

    def probe_http(self, ip: str, port: int = 80, use_https: bool = False) -> dict:
        """
        HTTP HEAD/GET probes to extract Server header and version from body.
        Returns dict with keys: server, body_snippet, detected_version.
        """
        scheme = "https" if use_https else "http"
        result = {"server": "", "body_snippet": "", "detected_version": ""}
        for path in self.HTTP_PATHS:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0 (Zeek device detector)")
                req.add_header("Accept", "application/json,text/html,*/*")
                # Disable SSL verification for embedded devices with self-signed certs
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=ctx if use_https else None) as resp:
                    server_hdr = resp.headers.get("Server", "")
                    content_type = resp.headers.get("Content-Type", "")
                    if server_hdr:
                        result["server"] = server_hdr
                    body = resp.read(2048).decode("utf-8", errors="replace")
                    result["body_snippet"] = body[:500]
                    # Try to extract version from JSON body
                    if "json" in content_type:
                        try:
                            data = json.loads(body)
                            for key in ["version", "firmware", "sw_version",
                                        "softwareVersion", "fwVersion",
                                        "applicationVersion", "model"]:
                                if key in data:
                                    result["detected_version"] = str(data[key])
                                    break
                        except json.JSONDecodeError:
                            pass
                    # Extract from HTML meta or title
                    ver_m = re.search(
                        r"(?i)version[\":\s>]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)", body)
                    if ver_m and not result["detected_version"]:
                        result["detected_version"] = ver_m.group(1)
                    if server_hdr or result["detected_version"]:
                        logger.info("HTTP probe %s%s → Server: %s ver: %s",
                                    url, path, server_hdr, result.get("detected_version"))
                        return result
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    # Device exists but requires auth — still log the Server header
                    result["server"] = e.headers.get("Server", result["server"])
                    if result["server"]:
                        return result
            except Exception as e:
                logger.debug("HTTP probe %s %s: %s", ip, path, e)
        return result

    def probe_modbus_device_id(self, ip: str, port: int = 502,
                                unit_id: int = 1) -> dict:
        """
        Modbus FC43 (Read Device Identification, MEI Type 14).
        Returns dict with basic (level 1) object strings:
          VendorName, ProductCode, MajorMinorRevision.
        """
        result = {}
        # FC43 request: transaction 0x0001, protocol 0x0000, length 5,
        # unit_id, FC=43, MEI type=14, read dev id=1, obj id=0
        request = struct.pack(">HHHBBBB", 0x0001, 0x0000, 0x0005,
                               unit_id, 0x2B, 0x0E, 0x01, 0x00)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(request)
                data = sock.recv(256)
                if len(data) < 9:
                    return result
                # Parse objects from response (offset 9 onwards)
                obj_names = ["VendorName", "ProductCode", "MajorMinorRevision",
                             "VendorURL", "ProductName", "ModelName"]
                i = 9
                obj_idx = 0
                while i < len(data) - 2 and obj_idx < len(obj_names):
                    obj_id = data[i]
                    obj_len = data[i + 1]
                    obj_val = data[i+2:i+2+obj_len].decode("ascii", errors="replace")
                    if obj_val.strip():
                        result[obj_names[obj_idx] if obj_idx < len(obj_names)
                               else f"obj_{obj_id}"] = obj_val.strip()
                    i += 2 + obj_len
                    obj_idx += 1
                logger.info("Modbus DevID %s: %s", ip, result)
        except Exception as e:
            logger.debug("Modbus probe %s: %s", ip, e)
        return result

    def probe_bacnet_iam(self, ip: str, port: int = 47808) -> dict:
        """
        Send BACnet Who-Is and listen for I-Am to extract vendor ID.
        Sends a broadcast-style unicast Who-Is to the target IP.
        """
        result = {}
        # BACnet/IP BVLC + NPDU + APDU Who-Is (all devices, no range)
        who_is = bytes([
            0x81, 0x0A,       # BVLC: original-unicast-NPDU
            0x00, 0x08,       # BVLC length = 8
            0x01, 0x20,       # NPDU: version=1, control (expecting reply)
            0xFF, 0xFF,       # dest net = broadcast
            0x10,             # APDU: unconfirmed service
            0x08,             # service choice: Who-Is (8)
        ])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(who_is, (ip, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    # Very simplified I-Am parse: find vendor ID
                    # Full parse would need a proper BACnet library
                    if len(data) >= 12 and data[6] == 0x10 and data[7] == 0x00:
                        # I-Am APDU: bytes 8+ contain object-id, max-apdu, seg,
                        # vendor-id in tagged encoding
                        # vendor ID tag = context tag 3 (0x39 or 0x21 for uint)
                        m = re.search(rb"\x09(.)", data[8:])
                        if m:
                            vendor_id = m.group(1)[0]
                            result["vendor_id"] = vendor_id
                            logger.info("BACnet I-Am from %s, vendor_id=%d",
                                        ip, vendor_id)
                except socket.timeout:
                    pass
        except Exception as e:
            logger.debug("BACnet probe %s: %s", ip, e)
        return result


# ---------------------------------------------------------------------------
# Batch enrichment helper
# ---------------------------------------------------------------------------
def enrich_devices(devices: List[Dict[str, Any]], prober: ActiveProber,
                   detector=None) -> List[Dict[str, Any]]:
    """
    Given a list of device dicts from detector.get_devices(),
    probe each one to fill in missing firmware/version data.
    Returns enriched list.
    """
    enriched = []
    for dev in devices:
        ip = dev.get("ip", "")
        if not ip:
            enriched.append(dev)
            continue

        logger.info("Enriching %s (%s %s)...", ip, dev.get("vendor"), dev.get("model"))

        # SNMP
        snmp = prober.probe_snmp(ip)
        if snmp:
            if not dev.get("firmware"):
                for key in ["entFirmwareRev", "apcSWVersion", "eatonFirmware",
                            "hrSWInstalledName"]:
                    if key in snmp:
                        dev["firmware"] = snmp[key]
                        break
            if not dev.get("hostname") and "sysName" in snmp:
                dev["hostname"] = snmp["sysName"]
            if snmp.get("sysDescr") and not dev.get("notes"):
                dev["notes"] = snmp["sysDescr"][:200]
            # Push to detector for pattern matching
            if detector:
                detector.process_snmp(
                    ip=ip, mac=dev.get("mac", ""),
                    sys_descr=snmp.get("sysDescr", ""),
                    sys_object_id=snmp.get("sysObjectID", ""),
                    sys_name=snmp.get("sysName", ""),
                    sys_location=snmp.get("sysLocation", ""),
                )

        # HTTP (ports 80, 443, 8080)
        for port, use_https in [(80, False), (443, True), (8080, False)]:
            http = prober.probe_http(ip, port=port, use_https=use_https)
            if http.get("detected_version") and not dev.get("firmware"):
                dev["firmware"] = http["detected_version"]
            if http.get("server"):
                if detector:
                    detector.process_http(ip=ip, mac=dev.get("mac", ""),
                                          server_header=http["server"],
                                          response_body_snippet=http.get("body_snippet",""))
            if http.get("server") or http.get("detected_version"):
                break

        # Modbus (port 502)
        if 502 in dev.get("open_ports", []) or dev.get("device_type") == "ot":
            modbus = prober.probe_modbus_device_id(ip)
            if modbus:
                if not dev.get("vendor") or dev.get("vendor") == "Unknown":
                    dev["vendor"] = modbus.get("VendorName", dev.get("vendor", ""))
                if not dev.get("model"):
                    dev["model"] = modbus.get("ProductCode", "")
                if not dev.get("firmware"):
                    dev["firmware"] = modbus.get("MajorMinorRevision", "")

        enriched.append(dev)

    return enriched


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        print("Usage: active_prober.py <ip> [community]")
        sys.exit(1)
    ip = sys.argv[1]
    community = sys.argv[2] if len(sys.argv) > 2 else "public"
    prober = ActiveProber(community=community)
    print("SNMP:", json.dumps(prober.probe_snmp(ip), indent=2))
    print("HTTP:", json.dumps(prober.probe_http(ip), indent=2))
    print("Modbus:", json.dumps(prober.probe_modbus_device_id(ip), indent=2))
    print("BACnet:", json.dumps(prober.probe_bacnet_iam(ip), indent=2))
