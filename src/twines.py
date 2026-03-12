"""
main.py
=======
Main entry point and self-test harness.

Modes:
  run     — Parse Zeek logs from a directory
  test    — Run built-in simulation tests (no Zeek required)
  report  — Generate reports from existing detected_devices.json
  enrich  — Actively probe detected devices (requires network access + auth)

Quick start:
  python main.py test                           # Simulate detection, print results
  python main.py run --log-dir /opt/zeek/logs/current --live
  python main.py run --log-dir /opt/zeek/logs/2024-01-15
  python main.py report --format html --output report.html
  python main.py enrich --community public      # ⚠️ Active probing!
"""

import os
import sys
import json
import time
import logging
import argparse

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from scripts.detector import DeviceDetector
from scripts.zeek_log_parser import ZeekLogOrchestrator, ZeekEventProcessor
from scripts.report_generator import report_console, report_html, report_csv

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simulated test events
# ---------------------------------------------------------------------------
SIMULATED_EVENTS = [
    # ── Medical devices ──────────────────────────────────────────────────────
    {
        "type": "dhcp",
        "ip": "10.1.1.10", "mac": "00:02:A5:11:22:33",
        "hostname": "IntelliVueMX800-ICU1",
        "vendor_class": "Philips IntelliVue MX800 R10.0",
        "param_req_list": [1, 3, 6, 15, 28, 43, 60],
    },
    {
        "type": "http",
        "ip": "10.1.1.10", "mac": "00:02:A5:11:22:33",
        "server_header": "Philips HC IntelliVue/R10.5.1",
        "user_agent": "",
    },
    {
        "type": "snmp",
        "ip": "10.1.1.10",
        "sys_descr": "Philips IntelliVue MX800 firmware R10.5.1 SN:DE12345",
        "sys_object_id": "1.3.6.1.4.1.1232.1.8000",
        "sys_name": "IntelliVueMX800-ICU1",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.20", "mac": "D4:61:9D:AA:BB:CC",
        "hostname": "ALARIS-8015-PUMP-02",
        "vendor_class": "AlarisPump/3.1.4.4",
        "param_req_list": [1, 3, 6, 15, 28, 43, 60, 66, 67],
    },
    {
        "type": "http",
        "ip": "10.1.1.20",
        "server_header": "Alaris Gateway/3.1.4.4",
        "user_agent": "AlarisPump/3.1.4.4",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.30", "mac": "00:0C:CE:DE:AD:BE",
        "hostname": "ZOLL-RSERIES-ED1",
        "vendor_class": "ZOLL R-Series v02.80.000 0000",
        "param_req_list": [1, 3, 6, 15, 43, 60],
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.40", "mac": "00:13:F7:12:34:56",
        "hostname": "OMNICELL-ADC-PHARM",
        "vendor_class": "OmnicellADC/8.3.1",
        "param_req_list": [1, 3, 6, 12, 15, 28, 43, 60, 77],
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.50", "mac": "F4:5C:89:AB:CD:EF",
        "hostname": "ACCU-CHEK-LAB1",
        "vendor_class": "AccuChek InformII SW2.04.14",
    },
    {
        "type": "snmp",
        "ip": "10.1.1.50",
        "sys_descr": "Roche Accu-Chek Inform II SW Version 2.04.14",
        "sys_object_id": "1.3.6.1.4.1.99999.1",
        "sys_name": "AccuCheckLab",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.60", "mac": "00:18:7D:11:22:33",
        "hostname": "iSTAT-DOWNLOADER-1",
        "vendor_class": "iSTAT Downloader/1.6.5",
    },
    {
        "type": "mdns",
        "ip": "10.1.1.70", "mac": "70:B3:D5:AA:BB:CC",
        "service_name": "Ceribell-RapidEEG-01._ceribell._tcp.local",
        "service_type": "_ceribell._tcp",
        "txt_records": {"firmware": "2.1.3", "model": "RapidResponseEEG"},
    },
    {
        "type": "hl7",
        "ip": "10.1.1.80", "mac": "00:15:F9:AA:BB:CC",
        "msh_segment": "MSH|^~\\&|ABL90|Radiometer|LIS||20240115120000||ORU^R01|001|P|2.5",
        "sending_application": "ABL90",
        "sending_facility": "Radiometer",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.90", "mac": "00:1A:4B:DE:AD:01",
        "hostname": "TRANSLOGIC-TUBE-01",
        "vendor_class": "Translogic/4.2.1",
    },
    {
        "type": "snmp",
        "ip": "10.1.1.100",
        "sys_descr": "Nihon Kohden EEG Monitor NeuroPack S1 SW 01-04-00",
        "sys_object_id": "1.3.6.1.4.1.30155.5.1",
        "sys_name": "NihonKohdenEEG",
    },
    {
        "type": "http",
        "ip": "10.1.1.110", "mac": "B4:99:4C:AB:CD:EF",
        "server_header": "Stryker SDC HD/2.3.1",
        "user_agent": "",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.120", "mac": "00:0A:8A:11:22:33",
        "hostname": "GE-VENUE-ECHO-1",
        "vendor_class": "GEVenue/R2.0.3",
    },
    {
        "type": "dhcp",
        "ip": "10.1.1.130", "mac": "00:0F:CB:CC:DD:EE",
        "hostname": "HILLROM-NAVICARE-GRS5",
        "vendor_class": "NaviCare GRS5 v3.1",
    },
    # ── OT Devices ────────────────────────────────────────────────────────────
    {
        "type": "snmp",
        "ip": "10.2.1.10",
        "sys_descr": "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AN:AP7811B SN:5A1234XY5)",
        "sys_object_id": "1.3.6.1.4.1.3808.1.1.1",
        "sys_name": "APC-PDU-RACK-A",
    },
    {
        "type": "snmp",
        "ip": "10.2.1.11",
        "sys_descr": "APC NetBotz 355 Wall (AOS v6.5.4)",
        "sys_object_id": "1.3.6.1.4.1.3808.1.1.9",
        "sys_name": "NetBotz-ICU-Hall",
    },
    {
        "type": "snmp",
        "ip": "10.2.1.20",
        "sys_descr": "EATON UPS Network Card (Powerware PX 9395 FW:01.45.0000)",
        "sys_object_id": "1.3.6.1.4.1.534.1.1",
        "sys_name": "EatonUPS-DataCenter",
    },
    {
        "type": "bacnet",
        "ip": "10.2.1.30", "mac": "00:1E:C0:AA:BB:CC",
        "vendor_id": 22,
        "object_name": "NAE-55-HVAC-FLOOR2",
        "model_name": "NAE5510-2",
        "application_sw_version": "8.1.0.5120",
        "firmware_revision": "8.1.0",
    },
    {
        "type": "bacnet",
        "ip": "10.2.1.31", "mac": "00:06:6E:11:22:33",
        "vendor_id": 22,
        "object_name": "NCE-25-AHU3",
        "model_name": "NCE2560",
        "application_sw_version": "8.1.0.5120",
    },
    {
        "type": "bacnet",
        "ip": "10.2.1.40", "mac": "00:07:4D:AA:BB:CC",
        "vendor_id": 83,
        "object_name": "ALC-CONTROLLER-RTU1",
        "model_name": "Zone Controller",
        "firmware_revision": "6.0.3.14",
    },
    {
        "type": "snmp",
        "ip": "10.2.1.50",
        "sys_descr": "Schneider Electric PowerLogic ION7330 FW 3.0.0",
        "sys_object_id": "1.3.6.1.4.1.3648.10",
        "sys_name": "ION7330-MDB",
    },
    {
        "type": "modbus",
        "ip": "10.2.1.50",
        "unit_id": 1,
        "device_id_str": "Read Input Registers",
    },
    {
        "type": "http",
        "ip": "10.2.1.60", "mac": "C0:2B:28:DE:AD:BE",
        "server_header": "TwinCAT/ADS Beckhoff Automation CX2040",
        "user_agent": "",
    },
    {
        "type": "port",
        "ip": "10.2.1.60",
        "port": 4840,
        "protocol": "tcp",
    },
    {
        "type": "dhcp",
        "ip": "10.2.1.70", "mac": "00:16:CB:AA:BB:CC",
        "hostname": "TEMPTRAK-WIFI-FREEZER1",
        "vendor_class": "TempTrak WiFi v2.3",
    },
    {
        "type": "snmp",
        "ip": "10.2.1.80",
        "sys_descr": "Chatsworth CPI POPS PDU Model SL8800A FW:1.4.3",
        "sys_object_id": "1.3.6.1.4.1.3028.1.1",
        "sys_name": "CPI-PDU-RACK-B",
    },

    # ── New devices ───────────────────────────────────────────────────────────

    # Brown's Medical Imaging — Shimadzu Radspeed Pro Room 1021
    {
        "type": "snmp",
        "ip": "10.3.1.10", "mac": "00:23:54:AA:BB:CC",
        "sys_descr": "Shimadzu Radspeed Pro DR System SW Ver 4.71 SN:MQ927EAb9002",
        "sys_object_id": "1.3.6.1.4.1.37310.1.1",
        "sys_name": "SHIMADZU-RADSPEED-1021",
    },

    # Brown's Medical Imaging — Shimadzu Radspeed Pro Room 3410
    {
        "type": "dhcp",
        "ip": "10.3.1.11", "mac": "00:23:54:DD:EE:FF",
        "hostname": "RADSPEED-3410-MQ92800F5002",
        "vendor_class": "Shimadzu Radspeed v4.60",
    },
    {
        "type": "http",
        "ip": "10.3.1.11",
        "server_header": "Shimadzu DR Console/4.60 SN:MQ92800F5002",
        "user_agent": "",
    },

    # Cassling — Siemens Sequoia #400-831892
    {
        "type": "snmp",
        "ip": "10.3.2.10", "mac": "D8:D0:90:11:22:33",
        "sys_descr": "Siemens Healthineers Sequoia Ultrasound VB23H SN:400-831892",
        "sys_object_id": "1.3.6.1.4.1.4329.1.10",
        "sys_name": "SIEMENS-SEQUOIA-01",
    },

    # Cassling — Siemens Sequoia #400-663369
    {
        "type": "dhcp",
        "ip": "10.3.2.11", "mac": "D8:D0:90:44:55:66",
        "hostname": "SEQUOIA-400-663369",
        "vendor_class": "Sequoia VB23H",
    },
    {
        "type": "port",
        "ip": "10.3.2.11",
        "port": 104,
        "protocol": "tcp",
    },

    # Abbott — Architect Ci4100 (chemistry module C402298 + immunoassay i1SR60348)
    {
        "type": "snmp",
        "ip": "10.3.3.10", "mac": "00:0D:56:AA:BB:CC",
        "sys_descr": "Abbott Architect Ci4100 Host SW 8.14 SN:C402298/i1SR60348",
        "sys_object_id": "1.3.6.1.4.1.1415.1.1",
        "sys_name": "ARCHITECT-CI4100-LAB",
    },
    {
        "type": "hl7",
        "ip": "10.3.3.10",
        "msh_segment": "MSH|^~\\&|Architect|Abbott|LIS||20240116090000||ORU^R01|002|P|2.5",
        "sending_application": "Architect",
        "sending_facility": "Abbott",
    },

    # Sysmex XN-430 SN:11480
    {
        "type": "snmp",
        "ip": "10.3.4.10", "mac": "44:A8:42:AA:BB:CC",
        "sys_descr": "Sysmex XN-430 Hematology Analyzer SW 00-11 SN:11480",
        "sys_object_id": "1.3.6.1.4.1.26576.1.1",
        "sys_name": "SYSMEX-XN430-HEME",
    },
    {
        "type": "hl7",
        "ip": "10.3.4.10",
        "msh_segment": "MSH|^~\\&|XN-430|Sysmex|LIS||20240116093000||ORU^R01|003|P|2.5",
        "sending_application": "XN-430",
        "sending_facility": "Sysmex",
    },

    # Cepheid GeneXpert SC SN:844555
    {
        "type": "snmp",
        "ip": "10.3.5.10", "mac": "00:26:B9:AA:BB:CC",
        "sys_descr": "Cepheid GeneXpert SC Xpertise 6.4 SN:844555",
        "sys_object_id": "1.3.6.1.4.1.38875.1.1",
        "sys_name": "GENEXPERT-SC-01",
    },

    # Cepheid GeneXpert SC SN:819851
    {
        "type": "dhcp",
        "ip": "10.3.5.11", "mac": "00:26:B9:CC:DD:EE",
        "hostname": "GENEXPERT-SC-819851",
        "vendor_class": "GeneXpert Xpertise 6.4",
    },

    # Cepheid GeneXpert SC SN:110009224
    {
        "type": "http",
        "ip": "10.3.5.12", "mac": "B8:AC:6F:11:22:33",
        "server_header": "Cepheid GeneXpert/6.4 SN:110009224",
        "user_agent": "",
    },

    # Cepheid GeneXpert SSC SN:110011567
    {
        "type": "snmp",
        "ip": "10.3.5.13", "mac": "B8:AC:6F:44:55:66",
        "sys_descr": "Cepheid GeneXpert SSC Xpertise 6.4 SN:110011567",
        "sys_object_id": "1.3.6.1.4.1.38875.1.2",
        "sys_name": "GENEXPERT-SSC-01",
    },
]


def run_simulation():
    """Simulate Zeek log events and run full detection pipeline."""
    print("\n" + "="*60)
    print("  ZEEK DEVICE DETECTOR — SIMULATION MODE")
    print("="*60)

    det = DeviceDetector(output_file="detected_devices_test.json", flush_interval=9999)

    for evt in SIMULATED_EVENTS:
        t = evt["type"]
        if t == "dhcp":
            det.process_dhcp(
                ip=evt["ip"], mac=evt.get("mac",""),
                hostname=evt.get("hostname",""),
                vendor_class=evt.get("vendor_class",""),
                param_req_list=evt.get("param_req_list",[]),
            )
        elif t == "http":
            det.process_http(
                ip=evt["ip"], mac=evt.get("mac",""),
                user_agent=evt.get("user_agent",""),
                server_header=evt.get("server_header",""),
            )
        elif t == "snmp":
            det.process_snmp(
                ip=evt["ip"], mac=evt.get("mac",""),
                sys_descr=evt.get("sys_descr",""),
                sys_object_id=evt.get("sys_object_id",""),
                sys_name=evt.get("sys_name",""),
            )
        elif t == "mdns":
            det.process_mdns(
                ip=evt["ip"], mac=evt.get("mac",""),
                service_name=evt.get("service_name",""),
                service_type=evt.get("service_type",""),
                txt_records=evt.get("txt_records",{}),
            )
        elif t == "bacnet":
            det.process_bacnet(
                ip=evt["ip"], mac=evt.get("mac",""),
                vendor_id=evt.get("vendor_id"),
                object_name=evt.get("object_name",""),
                model_name=evt.get("model_name",""),
                application_sw_version=evt.get("application_sw_version",""),
                firmware_revision=evt.get("firmware_revision",""),
            )
        elif t == "modbus":
            det.process_modbus(
                ip=evt["ip"], mac=evt.get("mac",""),
                unit_id=evt.get("unit_id",1),
                device_id_str=evt.get("device_id_str",""),
            )
        elif t == "hl7":
            det.process_hl7(
                ip=evt["ip"], mac=evt.get("mac",""),
                msh_segment=evt.get("msh_segment",""),
                sending_application=evt.get("sending_application",""),
                sending_facility=evt.get("sending_facility",""),
            )
        elif t == "port":
            det.process_port_observation(
                ip=evt["ip"], mac=evt.get("mac",""),
                port=evt.get("port",0),
                protocol=evt.get("protocol","tcp"),
            )

    devices = det.get_devices()

    # Console output
    report_console(devices)

    # HTML report
    report_html(devices, "detected_devices_report.html")

    # CSV
    report_csv(devices, "detected_devices.csv")

    # JSON
    with open("detected_devices_test.json", "w") as fh:
        json.dump(devices, fh, indent=2, default=str)

    print(f"\nOutput files written:")
    print("  detected_devices_test.json")
    print("  detected_devices_report.html")
    print("  detected_devices.csv")

    # Validation
    high = sum(1 for d in devices if d["confidence"] == "HIGH")
    med  = sum(1 for d in devices if d["confidence"] == "MEDIUM")
    low  = sum(1 for d in devices if d["confidence"] == "LOW")
    print(f"\nConfidence summary:  HIGH={high}  MEDIUM={med}  LOW={low}")

    return devices


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Zeek Medical/OT Device Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", help="Operation mode")

    # run
    p_run = sub.add_parser("run", help="Parse Zeek log directory")
    p_run.add_argument("--log-dir", required=True, help="Zeek log directory")
    p_run.add_argument("--live", action="store_true", help="Tail logs (live mode)")
    p_run.add_argument("--output", default="detected_devices.json")
    p_run.add_argument("--flush-interval", type=int, default=60)

    # test
    sub.add_parser("test", help="Run built-in simulation test")

    # report
    p_rep = sub.add_parser("report", help="Generate report from JSON")
    p_rep.add_argument("--input", default="detected_devices.json")
    p_rep.add_argument("--format", choices=["console","html","csv"],
                       default="console")
    p_rep.add_argument("--output", default="")

    # enrich (active)
    p_enr = sub.add_parser("enrich", help="Actively probe detected devices ⚠️")
    p_enr.add_argument("--input", default="detected_devices.json")
    p_enr.add_argument("--community", default="public", help="SNMP community")
    p_enr.add_argument("--timeout", type=float, default=2.0)
    p_enr.add_argument("--output", default="detected_devices_enriched.json")

    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG","INFO","WARNING","ERROR"])

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.mode == "test" or args.mode is None:
        run_simulation()

    elif args.mode == "run":
        det = DeviceDetector(output_file=args.output,
                             flush_interval=args.flush_interval)
        orch = ZeekLogOrchestrator(log_dir=args.log_dir,
                                   detector=det, live=args.live)
        if args.live:
            orch.process_live()
        else:
            orch.process_batch()

    elif args.mode == "report":
        with open(args.input) as fh:
            devices = json.load(fh)
        if args.format == "console":
            report_console(devices)
        elif args.format == "html":
            out = args.output or "report.html"
            report_html(devices, out)
        elif args.format == "csv":
            out = args.output or "devices.csv"
            report_csv(devices, out)

    elif args.mode == "enrich":
        from scripts.active_prober import ActiveProber, enrich_devices
        with open(args.input) as fh:
            devices = json.load(fh)
        det = DeviceDetector(flush_interval=9999)
        prober = ActiveProber(community=args.community, timeout=args.timeout)
        enriched = enrich_devices(devices, prober, det)
        with open(args.output, "w") as fh:
            json.dump(enriched, fh, indent=2, default=str)
        print(f"Enriched {len(enriched)} devices → {args.output}")
        report_console(enriched)


if __name__ == "__main__":
    main()
