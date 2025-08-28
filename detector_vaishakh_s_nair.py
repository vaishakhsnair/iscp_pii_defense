#!/usr/bin/env python3
import sys
import csv
import json
import re

# Regex definitions for standalone PII
REGEX_PATTERNS = {
    "phone": re.compile(r"\b\d{10}\b"),
    "aadhar": re.compile(r"\b\d{12}\b"),
    "passport": re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6}\b"),
    "upi": re.compile(r"\b[\w.-]+@[\w]+\b"),
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

def mask_value(key, value):
    if not value:
        return value
    if key in ("phone", "contact"):
        return value[:2] + "XXXXXX" + value[-2:]
    if key == "aadhar":
        return value[:4] + " XXXX XXXX"
    if key == "passport":
        return value[0] + "XXXXXXX"
    if key == "upi_id":
        return "XXXX@upi"
    if key == "email":
        parts = value.split("@")
        return parts[0][:2] + "XXX@" + parts[1] if len(parts) > 1 else "[REDACTED_EMAIL]"
    if key == "name":
        return " ".join([w[0] + "XXX" for w in value.split()])
    if key in ("address", "ip_address", "device_id"):
        return "[REDACTED_PII]"
    return value

def safe_json_loads(record_str):
    # Try to load JSON without Crashing on invalid Input, try and fix common issues if broken. else leaves empty
    try:
        return json.loads(record_str)
    except:
        try:
            fixed = record_str.replace("'", '"')
            fixed = re.sub(r",\s*}", "}", fixed)
            fixed = re.sub(r",\s*]", "]", fixed)
            return json.loads(fixed)
        except:
            return {}

def detect_and_redact(record_json):
    is_pii = False
    data = safe_json_loads(record_json)

    combinatorial_flags = {"name": False, "email": False, "address": False, "ip": False}

    for key, val in data.items():
        if val is None:
            continue
        val_str = str(val)

        if key in ("phone", "contact") and REGEX_PATTERNS["phone"].search(val_str):
            data[key] = mask_value("phone", val_str); is_pii = True
        elif key == "aadhar" and REGEX_PATTERNS["aadhar"].search(val_str):
            data[key] = mask_value("aadhar", val_str); is_pii = True
        elif key == "passport" and REGEX_PATTERNS["passport"].search(val_str):
            data[key] = mask_value("passport", val_str); is_pii = True
        elif key == "upi_id" and REGEX_PATTERNS["upi"].search(val_str):
            data[key] = mask_value("upi_id", val_str); is_pii = True
        elif key == "email" and REGEX_PATTERNS["email"].search(val_str):
            combinatorial_flags["email"] = True
            data[key] = mask_value("email", val_str)
        elif key == "name" and len(val_str.split()) >= 2:
            combinatorial_flags["name"] = True
            data[key] = mask_value("name", val_str)
        elif key == "address":
            combinatorial_flags["address"] = True
            data[key] = mask_value("address", val_str)
        elif key in ("ip_address", "device_id") and REGEX_PATTERNS["ip"].search(val_str):
            combinatorial_flags["ip"] = True
            data[key] = mask_value("ip_address", val_str)

    if sum(combinatorial_flags.values()) >= 2:
        is_pii = True

    return json.dumps(data), is_pii

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_vaishakh_s_nair.py input.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "redacted_output_vaishakh_s_nair.csv"

    with open(input_file, "r", newline="", encoding="utf-8-sig") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            redacted_json, is_pii = detect_and_redact(row["data_json"])
            writer.writerow({
                "record_id": row["record_id"],
                "redacted_data_json": redacted_json,
                "is_pii": str(is_pii)
            })

    print(f"Output written to {output_file}")

if __name__ == "__main__":
    main()
