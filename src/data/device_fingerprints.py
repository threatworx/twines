"""
Device Fingerprint Database
============================
Contains OUI prefixes, DHCP fingerprints, HTTP User-Agents, mDNS/Bonjour patterns,
SNMP OIDs, Modbus/BACnet signatures, and network behavior patterns for each target device.

Detection confidence levels:
  HIGH   - unique identifier (serial, model string, specific OID)
  MEDIUM - combination of OUI + protocol behavior
  LOW    - OUI alone or single weak signal
"""

# ---------------------------------------------------------------------------
# MAC OUI → Vendor map (primary 24-bit prefix, some 36-bit for disambiguation)
# ---------------------------------------------------------------------------
OUI_MAP = {
    # Alaris / BD (Becton Dickinson acquired Alaris)
    "00:40:9D": {"vendor": "Alaris", "notes": "Alaris Systems (pre-BD)"},
    "00:1C:B3": {"vendor": "Alaris/BD", "notes": "BD Alaris infusion pumps"},
    "D4:61:9D": {"vendor": "Alaris/BD", "notes": "BD Alaris 8015 PC Unit"},

    # Philips Healthcare
    "00:02:A5": {"vendor": "Philips", "notes": "Philips Healthcare monitors"},
    "00:50:77": {"vendor": "Philips", "notes": "Philips Medical Systems"},
    "A8:5E:45": {"vendor": "Philips", "notes": "Philips patient monitors (MX series)"},
    "00:1E:8C": {"vendor": "Philips", "notes": "Philips IntelliVue"},
    "90:E6:BA": {"vendor": "Philips", "notes": "Philips IntelliVue MX/X series"},
    "00:22:37": {"vendor": "Philips", "notes": "Philips Healthcare"},
    "D8:50:E6": {"vendor": "Philips", "notes": "Philips IntelliVue MX800"},

    # Hill-Rom / Baxter (acquired Hill-Rom 2021)
    "00:0F:CB": {"vendor": "Hill-Rom", "notes": "Hill-Rom NaviCare"},
    "00:1D:43": {"vendor": "Hill-Rom", "notes": "Hill-Rom nurse call systems"},
    "B8:27:EB": {"vendor": "Raspberry Pi", "notes": "Hill-Rom NaviCare uses RPi-based controllers"},

    # Omnicell
    "00:13:F7": {"vendor": "Omnicell", "notes": "Omnicell dispensing cabinets"},
    "00:24:E8": {"vendor": "Omnicell", "notes": "Omnicell ADC"},

    # Swisslog / Translogic
    "00:1A:4B": {"vendor": "Swisslog", "notes": "Translogic tube stations"},
    "00:0A:CD": {"vendor": "Swisslog", "notes": "Swisslog Healthcare"},

    # Zoll Medical
    "00:0C:CE": {"vendor": "Zoll", "notes": "Zoll defibrillators"},
    "00:11:5E": {"vendor": "Zoll", "notes": "Zoll R-Series"},
    "00:22:A7": {"vendor": "Zoll", "notes": "Zoll Medical devices"},

    # Abbott / i-STAT / Libre
    "00:18:7D": {"vendor": "Abbott", "notes": "Abbott i-STAT"},
    "00:1C:4D": {"vendor": "Abbott", "notes": "Abbott diagnostics"},
    "A4:5E:60": {"vendor": "Abbott", "notes": "Abbott FreeStyle/i-STAT wireless"},

    # Roche Diagnostics
    "00:0D:93": {"vendor": "Roche", "notes": "Roche Diagnostics"},
    "00:1A:2B": {"vendor": "Roche", "notes": "Roche Accu-Chek"},
    "F4:5C:89": {"vendor": "Roche", "notes": "Roche Accu-Chek Inform II"},

    # Cadwell
    "00:20:4C": {"vendor": "Cadwell", "notes": "Cadwell EEG workstations"},

    # Stryker
    "00:15:8B": {"vendor": "Stryker", "notes": "Stryker SDC/SurgiCount"},
    "B4:99:4C": {"vendor": "Stryker", "notes": "Stryker surgical systems"},

    # GE Healthcare
    "00:09:9A": {"vendor": "GE Healthcare", "notes": "GE medical imaging"},
    "00:0D:B2": {"vendor": "GE Healthcare", "notes": "GE Venue ultrasound"},
    "78:1D:4F": {"vendor": "GE Healthcare", "notes": "GE Healthcare devices"},

    # Nihon Kohden
    "00:0A:8A": {"vendor": "Nihon Kohden", "notes": "Nihon Kohden EEG/ECG monitors"},
    "00:1B:21": {"vendor": "Nihon Kohden", "notes": "Nihon Kohden patient monitors"},

    # Ceribell
    "70:B3:D5": {"vendor": "Ceribell", "notes": "Ceribell Rapid Response EEG"},

    # Radiometer
    "00:15:F9": {"vendor": "Radiometer", "notes": "Radiometer ABL90 FLEX PLUS"},
    "00:50:C2": {"vendor": "Radiometer", "notes": "Radiometer blood gas analyzers"},

    # APC / Schneider Electric (APC is SE brand)
    "00:C0:B7": {"vendor": "APC", "notes": "APC by Schneider Electric PDUs"},
    "00:21:55": {"vendor": "APC", "notes": "APC NetBotz"},
    "28:29:86": {"vendor": "APC", "notes": "APC Smart-UPS / MasterSwitchPDU2"},
    "74:AC:B9": {"vendor": "APC", "notes": "APC AP7811B"},
    "00:60:26": {"vendor": "APC", "notes": "APC older PDUs"},

    # Cooper-Atkins
    "00:16:CB": {"vendor": "Cooper-Atkins", "notes": "TempTrak WiFi Sensor"},

    # Eaton
    "00:09:60": {"vendor": "Eaton", "notes": "Eaton UPS network cards"},
    "00:1D:BE": {"vendor": "Eaton", "notes": "Eaton Power Xpert"},
    "F0:DE:F1": {"vendor": "Eaton", "notes": "Eaton UPS"},

    # Automated Logic / Carrier
    "00:07:4D": {"vendor": "Automated Logic", "notes": "ALC BACnet controllers"},
    "00:15:F0": {"vendor": "Automated Logic", "notes": "Automated Logic WebCTRL"},

    # Schneider Electric (non-APC)
    "00:80:F4": {"vendor": "Schneider Electric", "notes": "Schneider PowerLogic ION"},
    "88:9F:FA": {"vendor": "Schneider Electric", "notes": "Schneider Electric PowerLogic ION7330"},
    "A8:9F:BA": {"vendor": "Schneider Electric", "notes": "Schneider Electric building automation"},

    # Johnson Controls
    "00:1E:C0": {"vendor": "Johnson Controls", "notes": "JCI NAE/NCE controllers"},
    "00:06:6E": {"vendor": "Johnson Controls", "notes": "Johnson Controls BACnet"},
    "00:50:56": {"vendor": "VMware", "notes": "JCI Metasys often runs on VMware"},

    # Beckhoff
    "00:01:05": {"vendor": "Beckhoff", "notes": "Beckhoff Automation TwinCAT"},
    "C0:2B:28": {"vendor": "Beckhoff", "notes": "Beckhoff EK/CX series"},

    # Chatsworth Products
    "00:C0:4E": {"vendor": "Chatsworth Products", "notes": "CPI PDUs"},
    "00:50:16": {"vendor": "Chatsworth Products", "notes": "Chatsworth PDU older series"},

    # Shimadzu (medical imaging / X-ray)
    "00:0E:0C": {"vendor": "Shimadzu", "notes": "Shimadzu medical imaging systems"},
    "00:23:54": {"vendor": "Shimadzu", "notes": "Shimadzu Radspeed radiography"},
    "00:1B:78": {"vendor": "Shimadzu", "notes": "Shimadzu digital radiography"},

    # Siemens Healthineers (ultrasound / imaging)
    "00:00:29": {"vendor": "Siemens Healthineers", "notes": "Siemens medical imaging"},
    "00:1B:1B": {"vendor": "Siemens Healthineers", "notes": "Siemens Sequoia / Acuson ultrasound"},
    "00:50:DA": {"vendor": "Siemens Healthineers", "notes": "Siemens Healthineers devices"},
    "00:E0:4C": {"vendor": "Siemens Healthineers", "notes": "Siemens imaging workstations"},
    "D8:D0:90": {"vendor": "Siemens Healthineers", "notes": "Siemens Sequoia ultrasound"},

    # Sysmex (hematology analyzers)
    "00:0C:29": {"vendor": "Sysmex", "notes": "Sysmex hematology analyzers (VMware NIC common)"},
    "00:17:C8": {"vendor": "Sysmex", "notes": "Sysmex XN-series analyzers"},
    "00:1D:92": {"vendor": "Sysmex", "notes": "Sysmex Corporation"},
    "44:A8:42": {"vendor": "Sysmex", "notes": "Sysmex XN-series network adapter"},

    # Cepheid (molecular diagnostics / GeneXpert)
    "00:26:B9": {"vendor": "Cepheid", "notes": "Cepheid GeneXpert systems"},
    "00:1A:8C": {"vendor": "Cepheid", "notes": "Cepheid GeneXpert SC/SSC"},
    "B8:AC:6F": {"vendor": "Cepheid", "notes": "Cepheid GeneXpert instrument"},

    # Abbott (expanded — Architect series)
    "00:0D:56": {"vendor": "Abbott", "notes": "Abbott Diagnostics Architect series"},
    "00:26:08": {"vendor": "Abbott", "notes": "Abbott Architect clinical chemistry"},
}

# ---------------------------------------------------------------------------
# DHCP Fingerprints (Option 55 - Parameter Request List combos)
# ---------------------------------------------------------------------------
DHCP_FINGERPRINTS = {
    # Format: tuple of option numbers (sorted) → device info
    (1, 3, 6, 15, 28, 43, 60, 66, 67): {
        "vendor": "Alaris", "model": "8015 PC Unit",
        "notes": "Alaris pump DHCP PRL with vendor class 60"
    },
    (1, 3, 6, 15, 28, 43, 60): {
        "vendor": "Philips", "model": "IntelliVue",
        "notes": "Philips monitor DHCP fingerprint"
    },
    (1, 3, 6, 12, 15, 28, 43, 60, 77): {
        "vendor": "Omnicell", "model": "ADC",
        "notes": "Omnicell DHCP with user class option 77"
    },
    (1, 3, 6, 15, 43, 60): {
        "vendor": "Zoll", "model": "R-Series",
        "notes": "Zoll defibrillator DHCP"
    },
    (1, 3, 6, 12, 15, 28, 43): {
        "vendor": "GE Healthcare", "model": "Venue",
        "notes": "GE ultrasound DHCP PRL"
    },
    (1, 3, 6, 15, 28, 40, 41, 42): {
        "vendor": "APC", "model": "PDU/UPS",
        "notes": "APC network management card DHCP"
    },
    (1, 3, 6, 15, 28, 43, 60, 128, 129, 130, 131, 132, 133, 134, 135): {
        "vendor": "Beckhoff", "model": "TwinCAT PLC",
        "notes": "Beckhoff PXE boot DHCP"
    },
    # Shimadzu Radspeed — Windows Embedded based, requests TFTP options
    (1, 3, 6, 15, 28, 43, 60, 66, 67, 43): {
        "vendor": "Shimadzu", "model": "Radspeed Pro",
        "notes": "Shimadzu DR system DHCP PRL"
    },
    # Siemens Sequoia — Linux-based ultrasound
    (1, 3, 6, 12, 15, 28, 43, 60): {
        "vendor": "Siemens Healthineers", "model": "Sequoia",
        "notes": "Siemens Sequoia ultrasound DHCP"
    },
    # Sysmex XN-series — embedded Linux
    (1, 3, 6, 12, 15, 28, 43): {
        "vendor": "Sysmex", "model": "XN-series",
        "notes": "Sysmex hematology analyzer DHCP PRL"
    },
    # Cepheid GeneXpert — Windows Embedded
    (1, 3, 6, 15, 44, 46, 47, 31, 33, 43, 60): {
        "vendor": "Cepheid", "model": "GeneXpert",
        "notes": "Cepheid GeneXpert Windows Embedded DHCP"
    },
}

# DHCP Vendor Class Identifier (Option 60) strings
DHCP_VENDOR_CLASS = {
    "NaviCare":          {"vendor": "Hill-Rom", "model": "NaviCare (generic)"},
    "GRS5":              {"vendor": "Hill-Rom", "model": "NaviCare GRS5"},
    "GRS10":             {"vendor": "Hill-Rom", "model": "NaviCare GRS10"},
    "TempTrak":          {"vendor": "Cooper-Atkins", "model": "TempTrak WiFi Sensor"},
    "AlarisPump":        {"vendor": "Alaris",   "model": "8015 PC Unit"},
    "iSTAT":             {"vendor": "Abbott",   "model": "i-STAT"},
    "FreeStyle":         {"vendor": "Abbott",   "model": "FreeStyle Precision Pro"},
    "PHILIPS":           {"vendor": "Philips",  "model": "IntelliVue (generic)"},
    "IntelliVue":        {"vendor": "Philips",  "model": "IntelliVue"},
    "MX40":              {"vendor": "Philips",  "model": "IntelliVue MX40"},
    "MX450":             {"vendor": "Philips",  "model": "IntelliVue MX450"},
    "MX500":             {"vendor": "Philips",  "model": "IntelliVue MX500"},
    "MX800":             {"vendor": "Philips",  "model": "IntelliVue MX800"},
    "VS30":              {"vendor": "Philips",  "model": "EarlyVue VS30"},
    "VS4":               {"vendor": "Philips",  "model": "SureSigns VS4"},
    "PageWriter":        {"vendor": "Philips",  "model": "PageWriter ECG"},
    "OmnicellADC":       {"vendor": "Omnicell", "model": "Automated Dispensing Cabinet"},
    "Translogic":        {"vendor": "Swisslog", "model": "Translogic Tube Station"},
    "ZOLL":              {"vendor": "Zoll",     "model": "R-Series"},
    "AccuChek":          {"vendor": "Roche",    "model": "Accu-Chek Inform II"},
    "Cascade":           {"vendor": "Cadwell",  "model": "Cascade Workstation"},
    "Ceribell":          {"vendor": "Ceribell", "model": "Rapid Response EEG Recorder"},
    "Radiometer":        {"vendor": "Radiometer", "model": "ABL90 FLEX PLUS"},
    "SDC":               {"vendor": "Stryker",  "model": "SDC HD"},
    "SurgiCount":        {"vendor": "Stryker",  "model": "SurgiCount Tablet"},
    "GEVenue":           {"vendor": "GE Healthcare", "model": "Venue"},
    "NihonKohden":       {"vendor": "Nihon Kohden", "model": "EEG Monitor"},
    "APC":               {"vendor": "APC",      "model": "PDU/UPS (generic)"},
    "MasterSwitch":      {"vendor": "APC",      "model": "MasterSwitchPDU2"},
    "NetBotz":           {"vendor": "APC",      "model": "NetBotz 355 Wall"},
    "Eaton":             {"vendor": "Eaton",    "model": "UPS"},
    "PowerXpert":        {"vendor": "Eaton",    "model": "Power Xpert"},
    "ION":               {"vendor": "Schneider Electric", "model": "PowerLogic ION7330"},
    "TwinCAT":           {"vendor": "Beckhoff", "model": "TwinCAT PLC"},
    "Metasys":           {"vendor": "Johnson Controls", "model": "NAE/NCE"},
    "Chatsworth":        {"vendor": "Chatsworth Products", "model": "PDU"},
    # Shimadzu
    "Shimadzu":          {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "RadspeedPro":       {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "Radspeed":          {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    # Siemens Healthineers
    "Siemens":           {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "Sequoia":           {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "Acuson":            {"vendor": "Siemens Healthineers","model": "Acuson (generic)"},
    "SiemensHealthineers":{"vendor":"Siemens Healthineers","model": "Sequoia"},
    # Abbott Architect (expanded)
    "Architect":         {"vendor": "Abbott",              "model": "Architect Ci4100"},
    "ArchitectCi":       {"vendor": "Abbott",              "model": "Architect Ci4100"},
    "AbbottDiag":        {"vendor": "Abbott",              "model": "Architect (generic)"},
    # Sysmex
    "Sysmex":            {"vendor": "Sysmex",              "model": "XN-series"},
    "XN-430":            {"vendor": "Sysmex",              "model": "XN-430"},
    "XN430":             {"vendor": "Sysmex",              "model": "XN-430"},
    # Cepheid
    "Cepheid":           {"vendor": "Cepheid",             "model": "GeneXpert"},
    "GeneXpert":         {"vendor": "Cepheid",             "model": "GeneXpert"},
    "GX":                {"vendor": "Cepheid",             "model": "GeneXpert"},
}

# ---------------------------------------------------------------------------
# HTTP User-Agent / Server Header patterns
# ---------------------------------------------------------------------------
HTTP_PATTERNS = [
    # Alaris
    {"pattern": r"Alaris|8015|AlarisPump",      "vendor": "Alaris",   "model": "8015 PC Unit",     "field": "ua"},
    # Philips
    {"pattern": r"IntelliVue",                   "vendor": "Philips",  "model": "IntelliVue",        "field": "ua"},
    {"pattern": r"EarlyVue\s*VS30",              "vendor": "Philips",  "model": "EarlyVue VS30",     "field": "ua"},
    {"pattern": r"MX\s*40\b",                    "vendor": "Philips",  "model": "IntelliVue MX40",   "field": "ua"},
    {"pattern": r"MX\s*450\b",                   "vendor": "Philips",  "model": "IntelliVue MX450",  "field": "ua"},
    {"pattern": r"MX\s*500\b",                   "vendor": "Philips",  "model": "IntelliVue MX500",  "field": "ua"},
    {"pattern": r"MX\s*800\b",                   "vendor": "Philips",  "model": "IntelliVue MX800",  "field": "ua"},
    {"pattern": r"MMS\s*X2|MMSX2",               "vendor": "Philips",  "model": "IntelliVue MMS X2", "field": "ua"},
    {"pattern": r"PageWriter",                    "vendor": "Philips",  "model": "PageWriter ECG",    "field": "ua"},
    {"pattern": r"SureSigns\s*VS4",              "vendor": "Philips",  "model": "SureSigns VS4",     "field": "ua"},
    {"pattern": r"IntelliVue\s*X3\b",            "vendor": "Philips",  "model": "IntelliVue X3",     "field": "ua"},
    # Philips web server headers
    {"pattern": r"Philips\s*HC|PHC/",            "vendor": "Philips",  "model": "IntelliVue (web)",  "field": "server"},
    # Hill-Rom
    {"pattern": r"NaviCare|Hill-?Rom",           "vendor": "Hill-Rom", "model": "NaviCare",          "field": "ua"},
    {"pattern": r"GRS\s*5\b",                    "vendor": "Hill-Rom", "model": "NaviCare GRS5",     "field": "ua"},
    {"pattern": r"GRS\s*10\b",                   "vendor": "Hill-Rom", "model": "NaviCare GRS10",    "field": "ua"},
    # Omnicell
    {"pattern": r"Omnicell|OmniRx",              "vendor": "Omnicell", "model": "Automated Dispensing Cabinet", "field": "ua"},
    # Swisslog
    {"pattern": r"Translogic|Swisslog",          "vendor": "Swisslog", "model": "Translogic Tube Station", "field": "ua"},
    # Zoll
    {"pattern": r"ZOLL\s*R-?Series|ZollRSeries","vendor": "Zoll",    "model": "R-Series",          "field": "ua"},
    # Abbott
    {"pattern": r"i-?STAT|iSTAT",               "vendor": "Abbott",  "model": "i-STAT",             "field": "ua"},
    {"pattern": r"FreeStyle\s*Precision",        "vendor": "Abbott",  "model": "FreeStyle Precision Pro", "field": "ua"},
    # Roche
    {"pattern": r"Accu-?Chek|AccuChek",          "vendor": "Roche",   "model": "Accu-Chek Inform II","field": "ua"},
    # Cadwell
    {"pattern": r"Cascade\s*Workstation|Cadwell","vendor": "Cadwell", "model": "Cascade Workstation","field": "ua"},
    # Stryker (can appear in either Server header or User-Agent)
    {"pattern": r"SDC\s*HD|Stryker\s*SDC",       "vendor": "Stryker", "model": "SDC HD",             "field": "server"},
    {"pattern": r"SDC\s*HD|Stryker\s*SDC",       "vendor": "Stryker", "model": "SDC HD",             "field": "ua"},
    {"pattern": r"SurgiCount",                    "vendor": "Stryker", "model": "SurgiCount Tablet",  "field": "server"},
    {"pattern": r"SurgiCount",                    "vendor": "Stryker", "model": "SurgiCount Tablet",  "field": "ua"},
    # GE
    {"pattern": r"GE\s*Venue|Venue\s*Ultrasound","vendor": "GE Healthcare", "model": "Venue",        "field": "ua"},
    # Nihon Kohden
    {"pattern": r"Nihon\s*Kohden|NihonKohden",   "vendor": "Nihon Kohden", "model": "EEG Monitor",   "field": "ua"},
    # Ceribell
    {"pattern": r"Ceribell|RapidResponse\s*EEG", "vendor": "Ceribell","model": "Rapid Response EEG Recorder","field": "ua"},
    # Radiometer
    {"pattern": r"ABL90|Radiometer",             "vendor": "Radiometer","model":"ABL90 FLEX PLUS",  "field": "ua"},
    # APC
    {"pattern": r"APC\s*Web|apcsetup|PowerNet",  "vendor": "APC",     "model": "PDU/UPS",            "field": "server"},
    {"pattern": r"NetBotz",                       "vendor": "APC",     "model": "NetBotz 355",        "field": "server"},
    {"pattern": r"AP7811",                        "vendor": "APC",     "model": "AP7811B",            "field": "server"},
    # Eaton
    {"pattern": r"Eaton|PowerXpert|PXGX",        "vendor": "Eaton",   "model": "UPS",                "field": "server"},
    # Schneider
    {"pattern": r"ION7330|PowerLogic",           "vendor": "Schneider Electric","model":"PowerLogic ION7330","field":"server"},
    # Johnson Controls
    {"pattern": r"Metasys|JCI\s*NAE|JCI\s*NCE", "vendor": "Johnson Controls","model":"NAE/NCE",      "field":"server"},
    # Beckhoff
    {"pattern": r"TwinCAT|Beckhoff",             "vendor": "Beckhoff","model": "TwinCAT PLC",        "field":"server"},
    # Chatsworth
    {"pattern": r"Chatsworth|CPI\s*PDU",         "vendor": "Chatsworth Products","model":"PDU",      "field":"server"},
    # Cooper-Atkins
    {"pattern": r"TempTrak|Cooper-?Atkins",       "vendor": "Cooper-Atkins","model":"TempTrak WiFi", "field":"ua"},
    # Automated Logic
    {"pattern": r"WebCTRL|Automated\s*Logic",    "vendor": "Automated Logic","model":"BACnet Controller","field":"server"},

    # Shimadzu Radspeed Pro (digital radiography)
    {"pattern": r"Shimadzu|Radspeed",            "vendor": "Shimadzu",            "model": "Radspeed Pro",  "field": "ua"},
    {"pattern": r"Shimadzu|Radspeed",            "vendor": "Shimadzu",            "model": "Radspeed Pro",  "field": "server"},
    # Serial numbers appear in SNMP/HTTP banners for asset correlation
    {"pattern": r"MQ927EAb9002|MQ92800F5002",   "vendor": "Shimadzu",            "model": "Radspeed Pro",  "field": "ua"},
    {"pattern": r"MQ927EAb9002|MQ92800F5002",   "vendor": "Shimadzu",            "model": "Radspeed Pro",  "field": "server"},

    # Siemens Healthineers Sequoia ultrasound
    {"pattern": r"Sequoia|Acuson",               "vendor": "Siemens Healthineers","model": "Sequoia",       "field": "ua"},
    {"pattern": r"Sequoia|Acuson",               "vendor": "Siemens Healthineers","model": "Sequoia",       "field": "server"},
    {"pattern": r"Siemens\s*Healthineers",       "vendor": "Siemens Healthineers","model": "Sequoia",       "field": "server"},
    {"pattern": r"400-831892|400-663369",        "vendor": "Siemens Healthineers","model": "Sequoia",       "field": "ua"},
    {"pattern": r"400-831892|400-663369",        "vendor": "Siemens Healthineers","model": "Sequoia",       "field": "server"},

    # Abbott Architect Ci4100 (clinical chemistry / immunoassay combo)
    {"pattern": r"Architect\s*Ci|ArchitectCi",   "vendor": "Abbott",              "model": "Architect Ci4100","field": "ua"},
    {"pattern": r"Architect\s*Ci|ArchitectCi",   "vendor": "Abbott",              "model": "Architect Ci4100","field": "server"},
    {"pattern": r"C402298|i1SR60348",            "vendor": "Abbott",              "model": "Architect Ci4100","field": "ua"},
    {"pattern": r"C402298|i1SR60348",            "vendor": "Abbott",              "model": "Architect Ci4100","field": "server"},

    # Sysmex XN-430 hematology analyzer
    {"pattern": r"Sysmex|XN-?430\b",            "vendor": "Sysmex",              "model": "XN-430",        "field": "ua"},
    {"pattern": r"Sysmex|XN-?430\b",            "vendor": "Sysmex",              "model": "XN-430",        "field": "server"},
    # Serial number 11480
    {"pattern": r"\b11480\b",                    "vendor": "Sysmex",              "model": "XN-430",        "field": "ua"},

    # Cepheid GeneXpert SC / SSC (molecular diagnostics)
    {"pattern": r"GeneXpert|Gene\s*Xpert",       "vendor": "Cepheid",             "model": "GeneXpert",     "field": "ua"},
    {"pattern": r"GeneXpert|Gene\s*Xpert",       "vendor": "Cepheid",             "model": "GeneXpert",     "field": "server"},
    {"pattern": r"Cepheid",                      "vendor": "Cepheid",             "model": "GeneXpert",     "field": "server"},
    # Serial numbers for SC and SSC units
    {"pattern": r"844555|819851|110009224|110011567", "vendor": "Cepheid",        "model": "GeneXpert",     "field": "ua"},
    {"pattern": r"844555|819851|110009224|110011567", "vendor": "Cepheid",        "model": "GeneXpert",     "field": "server"},
]

# ---------------------------------------------------------------------------
# SNMP OID patterns (sysDescr, sysObjectID, enterprise OIDs)
# ---------------------------------------------------------------------------
SNMP_PATTERNS = {
    # Enterprise OID prefixes (from sysObjectID .1.3.6.1.2.1.1.2.0)
    "1.3.6.1.4.1.3808":  {"vendor": "APC",              "model": "PDU/UPS"},
    "1.3.6.1.4.1.534":   {"vendor": "Eaton",            "model": "UPS"},
    "1.3.6.1.4.1.3648":  {"vendor": "Schneider Electric","model": "PowerLogic ION"},
    "1.3.6.1.4.1.5935":  {"vendor": "Johnson Controls", "model": "Metasys NAE/NCE"},
    "1.3.6.1.4.1.4458":  {"vendor": "Beckhoff",         "model": "TwinCAT"},
    "1.3.6.1.4.1.14823": {"vendor": "Automated Logic",  "model": "WebCTRL"},
    "1.3.6.1.4.1.3028":  {"vendor": "Chatsworth Products","model": "PDU"},
    "1.3.6.1.4.1.30155": {"vendor": "Nihon Kohden",     "model": "EEG Monitor"},
    "1.3.6.1.4.1.2668":  {"vendor": "GE Healthcare",    "model": "Venue Ultrasound"},
    "1.3.6.1.4.1.31021": {"vendor": "Zoll",             "model": "R-Series"},
    "1.3.6.1.4.1.1232":  {"vendor": "Philips",          "model": "IntelliVue"},
    "1.3.6.1.4.1.887":   {"vendor": "Omnicell",         "model": "ADC"},
    "1.3.6.1.4.1.40418": {"vendor": "Ceribell",         "model": "Rapid Response EEG"},
    "1.3.6.1.4.1.21239": {"vendor": "Radiometer",       "model": "ABL90 FLEX PLUS"},
    # Shimadzu — enterprise OID under .37310 (Shimadzu Corporation IANA PEN)
    "1.3.6.1.4.1.37310": {"vendor": "Shimadzu",         "model": "Radspeed Pro"},
    # Siemens AG enterprise OID — Healthineers devices use Siemens parent OID
    "1.3.6.1.4.1.4329":  {"vendor": "Siemens Healthineers","model": "Sequoia"},
    # Sysmex — enterprise OID .26576
    "1.3.6.1.4.1.26576": {"vendor": "Sysmex",           "model": "XN-series"},
    # Cepheid — enterprise OID .38875
    "1.3.6.1.4.1.38875": {"vendor": "Cepheid",          "model": "GeneXpert"},
    # Abbott Diagnostics — enterprise OID .1415
    "1.3.6.1.4.1.1415":  {"vendor": "Abbott",           "model": "Architect (generic)"},

    # sysDescr substring patterns (check if OID string contains these)
    "sysDescr:AlarisPump":   {"vendor": "Alaris",   "model": "8015 PC Unit"},
    "sysDescr:IntelliVue":   {"vendor": "Philips",  "model": "IntelliVue"},
    "sysDescr:NaviCare":     {"vendor": "Hill-Rom", "model": "NaviCare"},
    "sysDescr:Omnicell":     {"vendor": "Omnicell", "model": "ADC"},
    "sysDescr:Translogic":   {"vendor": "Swisslog", "model": "Translogic Tube Station"},
    "sysDescr:ZOLL":         {"vendor": "Zoll",     "model": "R-Series"},
    "sysDescr:iSTAT":        {"vendor": "Abbott",   "model": "i-STAT"},
    "sysDescr:AccuChek":     {"vendor": "Roche",    "model": "Accu-Chek Inform II"},
    "sysDescr:Cascade":      {"vendor": "Cadwell",  "model": "Cascade Workstation"},
    "sysDescr:SurgiCount":   {"vendor": "Stryker",  "model": "SurgiCount Tablet"},
    "sysDescr:SDC":          {"vendor": "Stryker",  "model": "SDC HD"},
    "sysDescr:NetBotz":      {"vendor": "APC",      "model": "NetBotz 355"},
    "sysDescr:AP7811":       {"vendor": "APC",      "model": "AP7811B"},
    "sysDescr:PowerLogic":   {"vendor": "Schneider Electric","model":"PowerLogic ION7330"},
    "sysDescr:TwinCAT":      {"vendor": "Beckhoff", "model": "TwinCAT PLC"},
    "sysDescr:TempTrak":     {"vendor": "Cooper-Atkins","model":"TempTrak WiFi"},
    "sysDescr:WebCTRL":      {"vendor": "Automated Logic","model":"BACnet Controller"},
    "sysDescr:Metasys":      {"vendor": "Johnson Controls","model":"NAE/NCE"},
    "sysDescr:CPI":          {"vendor": "Chatsworth Products","model":"PDU"},
    # New vendors — sysDescr keyword matches
    "sysDescr:Shimadzu":     {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "sysDescr:Radspeed":     {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "sysDescr:MQ927EAb9002": {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "sysDescr:MQ92800F5002": {"vendor": "Shimadzu",            "model": "Radspeed Pro"},
    "sysDescr:Sequoia":      {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "sysDescr:Acuson":       {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "sysDescr:400-831892":   {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "sysDescr:400-663369":   {"vendor": "Siemens Healthineers","model": "Sequoia"},
    "sysDescr:Architect":    {"vendor": "Abbott",              "model": "Architect Ci4100"},
    "sysDescr:C402298":      {"vendor": "Abbott",              "model": "Architect Ci4100"},
    "sysDescr:i1SR60348":    {"vendor": "Abbott",              "model": "Architect Ci4100"},
    "sysDescr:Sysmex":       {"vendor": "Sysmex",              "model": "XN-430"},
    "sysDescr:XN-430":       {"vendor": "Sysmex",              "model": "XN-430"},
    "sysDescr:GeneXpert":    {"vendor": "Cepheid",             "model": "GeneXpert"},
    "sysDescr:Cepheid":      {"vendor": "Cepheid",             "model": "GeneXpert"},
    "sysDescr:844555":       {"vendor": "Cepheid",             "model": "GeneXpert SC"},
    "sysDescr:819851":       {"vendor": "Cepheid",             "model": "GeneXpert SC"},
    "sysDescr:110009224":    {"vendor": "Cepheid",             "model": "GeneXpert SC"},
    "sysDescr:110011567":    {"vendor": "Cepheid",             "model": "GeneXpert SSC"},
}

# ---------------------------------------------------------------------------
# mDNS / DNS-SD service type patterns
# ---------------------------------------------------------------------------
MDNS_PATTERNS = [
    {"pattern": r"_ipp\._tcp|_pdl-datastream",       "vendor": "Philips",  "model": "IntelliVue (print)"},
    {"pattern": r"IntelliVue|intellivue",             "vendor": "Philips",  "model": "IntelliVue"},
    {"pattern": r"NaviCare|navicare",                 "vendor": "Hill-Rom", "model": "NaviCare"},
    {"pattern": r"AlarisPump|alaris",                 "vendor": "Alaris",   "model": "8015 PC Unit"},
    {"pattern": r"OmniSupplier|omnicell",             "vendor": "Omnicell", "model": "ADC"},
    {"pattern": r"Translogic|translogic",             "vendor": "Swisslog", "model": "Translogic Tube Station"},
    {"pattern": r"TempTrak|Cooper",                   "vendor": "Cooper-Atkins","model":"TempTrak WiFi"},
    {"pattern": r"Ceribell|ceribell",                 "vendor": "Ceribell", "model": "Rapid Response EEG"},
    {"pattern": r"_bacnet\._udp",                     "vendor": "BACnet Device","model":"BACnet (generic)"},
    {"pattern": r"metasys",                           "vendor": "Johnson Controls","model":"Metasys NAE/NCE"},
    {"pattern": r"beckhoff|twincat",                  "vendor": "Beckhoff", "model": "TwinCAT"},
    {"pattern": r"netbotz",                           "vendor": "APC",      "model": "NetBotz 355"},
    {"pattern": r"_eaton\.|eaton-ups",                "vendor": "Eaton",    "model": "UPS"},
    # New vendors
    {"pattern": r"shimadzu|radspeed",                 "vendor": "Shimadzu",            "model": "Radspeed Pro"},
    {"pattern": r"sequoia|acuson",                    "vendor": "Siemens Healthineers","model": "Sequoia"},
    {"pattern": r"sysmex|xn-?430",                   "vendor": "Sysmex",              "model": "XN-430"},
    {"pattern": r"genexpert|gene.xpert|cepheid",      "vendor": "Cepheid",             "model": "GeneXpert"},
    {"pattern": r"architect.*ci|architectci",         "vendor": "Abbott",              "model": "Architect Ci4100"},
]

# ---------------------------------------------------------------------------
# BACnet Device Vendor IDs (from ASHRAE BACnet Vendor ID registry)
# ---------------------------------------------------------------------------
BACNET_VENDOR_IDS = {
    22:   {"vendor": "Johnson Controls", "model": "Metasys NAE/NCE"},
    83:   {"vendor": "Automated Logic",  "model": "WebCTRL Controller"},
    135:  {"vendor": "Schneider Electric","model":"PowerLogic / Andover"},
    260:  {"vendor": "Beckhoff",         "model": "TwinCAT BACnet"},
    8:    {"vendor": "Trane",            "model": "Tracer (reference)"},
}

# ---------------------------------------------------------------------------
# Modbus Unit IDs and known register map signatures
# ---------------------------------------------------------------------------
MODBUS_SIGNATURES = {
    # Schneider PowerLogic ION7330 uses Modbus TCP on port 502
    # Device identification register 0x0001 returns model
    "port_502_vendor": {
        "vendor": "Schneider Electric / Eaton / Generic OT",
        "model": "Unknown Modbus Device",
        "notes": "Modbus TCP device - cross-reference OUI"
    },
}

# ---------------------------------------------------------------------------
# HL7 / FHIR endpoint signatures (medical integration)
# ---------------------------------------------------------------------------
HL7_PATTERNS = [
    {"pattern": r"MSH\|.*Alaris",        "vendor": "Alaris",   "model": "8015 PC Unit"},
    {"pattern": r"MSH\|.*IntelliVue",    "vendor": "Philips",  "model": "IntelliVue"},
    {"pattern": r"MSH\|.*iSTAT",         "vendor": "Abbott",   "model": "i-STAT"},
    {"pattern": r"MSH\|.*AccuChek",      "vendor": "Roche",    "model": "Accu-Chek Inform II"},
    {"pattern": r"MSH\|.*Omnicell",      "vendor": "Omnicell", "model": "ADC"},
    {"pattern": r"MSH\|.*Radiometer",    "vendor": "Radiometer","model":"ABL90 FLEX PLUS"},
    {"pattern": r"MSH\|.*Nihon",         "vendor": "Nihon Kohden","model":"EEG Monitor"},
    # New vendors — HL7 sending application fields
    {"pattern": r"MSH\|.*Sysmex|MSH\|.*XN-?430",       "vendor": "Sysmex",              "model": "XN-430"},
    {"pattern": r"MSH\|.*Cepheid|MSH\|.*GeneXpert",     "vendor": "Cepheid",             "model": "GeneXpert"},
    {"pattern": r"MSH\|.*Architect",                     "vendor": "Abbott",              "model": "Architect Ci4100"},
    {"pattern": r"MSH\|.*Shimadzu|MSH\|.*Radspeed",     "vendor": "Shimadzu",            "model": "Radspeed Pro"},
    {"pattern": r"MSH\|.*Sequoia|MSH\|.*Acuson",        "vendor": "Siemens Healthineers","model": "Sequoia"},
]

# ---------------------------------------------------------------------------
# Known TCP/UDP port usages per vendor
# ---------------------------------------------------------------------------
KNOWN_PORTS = {
    # Medical
    2575:  [{"vendor": "Philips",  "model": "IntelliVue", "proto": "HL7 MLLP"}],
    3001:  [{"vendor": "Alaris",   "model": "8015 PC Unit","proto": "Alaris SOAP API"}],
    3002:  [{"vendor": "Alaris",   "model": "8015 PC Unit","proto": "Alaris data"}],
    4000:  [{"vendor": "Omnicell", "model": "ADC",         "proto": "Omnicell proprietary"}],
    4001:  [{"vendor": "Swisslog", "model": "Translogic",  "proto": "Tube station control"}],
    8080:  [{"vendor": "Multiple", "model": "Various",     "proto": "HTTP alternate"}],
    9100:  [{"vendor": "Stryker",  "model": "SDC HD",      "proto": "SDC video/print"}],
    11000: [{"vendor": "Philips",  "model": "IntelliVue MX series","proto": "Philips data export"}],
    11001: [{"vendor": "Philips",  "model": "IntelliVue",  "proto": "Philips alarm"}],
    24105: [{"vendor": "GE Healthcare","model":"Venue",    "proto": "GE DICOM"}],
    # DICOM (used by Shimadzu DR and Siemens Sequoia)
    104:   [{"vendor": "Shimadzu / Siemens Healthineers", "model": "DICOM device",
             "proto": "DICOM"}],
    11112: [{"vendor": "Shimadzu / Siemens Healthineers", "model": "DICOM TLS",
             "proto": "DICOM TLS"}],
    # Sysmex host interface (HL7 / serial-over-LAN)
    1023:  [{"vendor": "Sysmex",   "model": "XN-series",   "proto": "Sysmex host interface"}],
    # Cepheid GeneXpert management port
    443:   [{"vendor": "Cepheid",  "model": "GeneXpert",   "proto": "HTTPS management"}],
    8443:  [{"vendor": "Cepheid",  "model": "GeneXpert",   "proto": "GeneXpert secure API"}],
    # OT / BACnet / Modbus
    47808: [{"vendor": "BACnet",  "model": "BACnet device","proto": "BACnet/IP UDP"}],
    502:   [{"vendor": "Modbus",  "model": "Modbus device","proto": "Modbus TCP"}],
    4840:  [{"vendor": "OPC-UA",  "model": "OPC-UA server","proto": "OPC-UA / Beckhoff"}],
    1911:  [{"vendor": "Beckhoff","model": "TwinCAT",      "proto": "ADS/AMS"}],
    48898: [{"vendor": "Beckhoff","model": "TwinCAT ADS",  "proto": "ADS routing"}],
    # APC / Eaton
    3052:  [{"vendor": "APC",     "model": "PDU/UPS",      "proto": "APC PowerNet"}],
    161:   [{"vendor": "SNMP",    "model": "Any SNMP device","proto": "SNMP v1/v2c/v3"}],
    162:   [{"vendor": "SNMP",    "model": "Any SNMP device","proto": "SNMP Trap"}],
    # HL7
    2575:  [{"vendor": "Medical HL7","model":"MLLP device","proto": "HL7 v2.x MLLP"}],
}

# ---------------------------------------------------------------------------
# Version/firmware extraction regex patterns per vendor
# ---------------------------------------------------------------------------
FIRMWARE_REGEX = {
    "Philips IntelliVue": [
        r"(?i)firmware[:\s/]+([A-Za-z0-9\.\-_]+)",
        r"(?i)SW[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)Rev[:\s]+([A-Za-z0-9\.\-]+)",
        r"IntelliVue\s+([A-Z]+[0-9]+)\s+R([0-9]+\.[0-9]+)",
    ],
    "Alaris": [
        r"(?i)v([0-9]+\.[0-9]+\.[0-9]+)",
        r"AlarisPump/([0-9\.]+)",
    ],
    "APC": [
        r"(?i)APC\s+Web/([0-9\.]+)",
        r"(?i)apc_hw:\s*([A-Za-z0-9]+)",
        r"(?i)AOS\s+v([0-9\.]+)",
    ],
    "Eaton": [
        r"(?i)PXGX\s+([0-9\.]+)",
        r"(?i)firmware[:\s]+([0-9\.]+)",
    ],
    "Johnson Controls": [
        r"(?i)Metasys\s+([0-9]+\.[0-9]+)",
        r"(?i)NAE([0-9]+)\s+v([0-9\.]+)",
    ],
    "Beckhoff": [
        r"(?i)TwinCAT\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        r"(?i)CX[0-9]+\s+([A-Za-z0-9\.\-]+)",
    ],
    "Schneider Electric": [
        r"(?i)ION7330\s+FW\s*([0-9\.]+)",
        r"(?i)PowerLogic\s+([0-9\.]+)",
    ],
    "Zoll": [
        r"(?i)R-?Series\s+v?([0-9\.]+)",
        r"(?i)ZOLL/([0-9\.]+)",
    ],
    "Roche": [
        r"(?i)Accu-?Chek\s+([A-Za-z0-9\.]+)",
        r"(?i)SW\s+Version\s*[:\s]+([0-9\.]+)",
    ],
    "Radiometer": [
        r"(?i)ABL90\s+([A-Za-z0-9\.\-]+)",
        r"(?i)SW\s*([0-9]+\.[0-9]+\.[0-9]+)",
    ],
    "GE Healthcare": [
        r"(?i)Venue\s+([A-Za-z0-9]+)\s+v([0-9\.]+)",
        r"(?i)GE/([0-9\.]+)",
    ],
    "Abbott": [
        r"(?i)i-?STAT\s+([0-9A-Za-z\.\-]+)",
        r"(?i)FW[:\s]+([0-9\.]+)",
    ],
    "Shimadzu": [
        r"(?i)Radspeed\s+Pro\s+([A-Za-z0-9\.\-]+)",
        r"(?i)SW\s*[Vv]er(?:sion)?[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)v([0-9]+\.[0-9]+\.[0-9]+)",
    ],
    "Siemens Healthineers": [
        r"(?i)Sequoia\s+([A-Za-z0-9\.\-]+)",
        r"(?i)SW\s*[Vv]ersion[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)[Ff]irmware[:\s/]+([A-Za-z0-9\.\-_]+)",
        r"VB([0-9]+[A-Za-z0-9]*)",
    ],
    "Sysmex": [
        r"(?i)XN-?430\s+([A-Za-z0-9\.\-]+)",
        r"(?i)[Ss][Ww]\s*[Vv]er(?:sion)?[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)[Ff][Ww][:\s]+([0-9\.]+)",
    ],
    "Cepheid": [
        r"(?i)GeneXpert\s+([A-Za-z0-9\.\-]+)",
        r"(?i)Xpertise\s+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)[Ss]oftware\s+[Vv]ersion[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9\.\-]*)",
        r"(?i)GXSC[:\s]+([0-9]+\.[0-9]+)",
    ],
}

# ---------------------------------------------------------------------------
# Known Asset Registry
# Maps serial numbers to specific device instances.
# Used by the detector to match serial numbers observed in any protocol
# (SNMP sysDescr, HTTP banners, DHCP hostnames, HL7 MSH fields) to
# a named, inventoried device with a known owner/location context.
#
# Format:
#   serial_number → {vendor, model, owner, location, asset_tag (optional)}
# ---------------------------------------------------------------------------
KNOWN_ASSETS = {
    # Brown's Medical Imaging — Shimadzu Radspeed Pro X-ray systems
    "MQ927EAb9002": {
        "vendor": "Shimadzu", "model": "Radspeed Pro",
        "owner": "Brown's Medical Imaging", "location": "Room 1021",
        "asset_tag": "BMI-1021",
    },
    "MQ92800F5002": {
        "vendor": "Shimadzu", "model": "Radspeed Pro",
        "owner": "Brown's Medical Imaging", "location": "Room 3410",
        "asset_tag": "BMI-3410",
    },

    # Cassling — Siemens Sequoia ultrasound systems
    "400-831892": {
        "vendor": "Siemens Healthineers", "model": "Sequoia",
        "owner": "Cassling", "location": "Ultrasound Suite",
        "asset_tag": "CAS-SEQ-01",
    },
    "400-663369": {
        "vendor": "Siemens Healthineers", "model": "Sequoia",
        "owner": "Cassling", "location": "Ultrasound Suite",
        "asset_tag": "CAS-SEQ-02",
    },

    # Abbott — Architect Ci4100 (combined chemistry + immunoassay)
    # The Ci4100 is a pairing of the c4000 chemistry and i1000SR immunoassay modules
    "C402298": {
        "vendor": "Abbott", "model": "Architect c4000 (Ci4100 chemistry module)",
        "owner": "Abbott", "location": "Lab",
        "asset_tag": "ABT-CI400-CHEM",
    },
    "i1SR60348": {
        "vendor": "Abbott", "model": "Architect i1000SR (Ci4100 immunoassay module)",
        "owner": "Abbott", "location": "Lab",
        "asset_tag": "ABT-CI400-IMMUNO",
    },

    # Sysmex — XN-430 hematology analyzer
    "11480": {
        "vendor": "Sysmex", "model": "XN-430",
        "owner": "Sysmex", "location": "Hematology Lab",
        "asset_tag": "SYS-XN430-01",
    },

    # Cepheid GeneXpert — SC units (4-module) and SSC unit (16-module)
    "844555": {
        "vendor": "Cepheid", "model": "GeneXpert SC",
        "owner": "Cepheid", "location": "Molecular Diagnostics Lab",
        "asset_tag": "CEP-GX-SC-01",
    },
    "819851": {
        "vendor": "Cepheid", "model": "GeneXpert SC",
        "owner": "Cepheid", "location": "Molecular Diagnostics Lab",
        "asset_tag": "CEP-GX-SC-02",
    },
    "110009224": {
        "vendor": "Cepheid", "model": "GeneXpert SC",
        "owner": "Cepheid", "location": "Molecular Diagnostics Lab",
        "asset_tag": "CEP-GX-SC-03",
    },
    "110011567": {
        "vendor": "Cepheid", "model": "GeneXpert SSC",
        "owner": "Cepheid", "location": "Molecular Diagnostics Lab",
        "asset_tag": "CEP-GX-SSC-01",
    },
}

# Pre-compiled set of all known serial numbers for fast membership tests
KNOWN_SERIAL_NUMBERS = set(KNOWN_ASSETS.keys())
