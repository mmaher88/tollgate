#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pyjwt[crypto]>=2.10", "cryptography>=45", "requests>=2.32"]
# ///
"""Provision Tollgate's signing assets through the App Store Connect API.

Environment:
  ASC_KEY_ID     API key ID
  ASC_ISSUER_ID  issuer ID for a team key; leave empty for an individual key
  ASC_KEY_PATH   path to AuthKey_<KEYID>.p8

Commands (all idempotent):
  check        verify credentials, list what exists
  device       register the connected iPhone (or --udid/--name)
  bundle-ids   create the app and tunnel App IDs, enable Network Extensions and App Groups
  cert         create an Apple Development certificate and a macOS-compatible .p12
  profiles     (re)create development profiles and verify their entitlements
  setup        device, bundle-ids, cert (if missing), profiles
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import plistlib
import re
import secrets
import subprocess
import sys
from pathlib import Path

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "out"
API = "https://api.appstoreconnect.apple.com/v1"
CAPABILITIES = ("NETWORK_EXTENSIONS", "APP_GROUPS")


# ---------- pure helpers (unit tested) ----------

def load_config(path: Path) -> dict[str, str]:
    values = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r'^([A-Z_][A-Z0-9_]*)="?(.*?)"?$', line.strip())
        if m:
            values[m.group(1)] = m.group(2)
    return values


def make_token(key_id: str, issuer_id: str, private_key_pem: bytes, now: dt.datetime) -> str:
    iat = int(now.timestamp())
    claims = {"iat": iat, "exp": iat + 15 * 60, "aud": "appstoreconnect-v1"}
    if issuer_id:
        claims["iss"] = issuer_id
    else:
        claims["sub"] = "user"
    return jwt.encode(claims, private_key_pem, algorithm="ES256", headers={"kid": key_id, "typ": "JWT"})


def make_csr(private_key: rsa.RSAPrivateKey, common_name: str) -> str:
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(private_key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def make_p12(private_key, cert_der: bytes, password: str) -> bytes:
    cert = x509.load_der_x509_certificate(cert_der)
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder()
                  .kdf_rounds(50000)
                  .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                  .hmac_hash(hashes.SHA1())
                  .build(password.encode()))
    return pkcs12.serialize_key_and_certificates(b"Tollgate Development", private_key, cert, None, encryption)


def profile_plist(profile_bytes: bytes) -> dict:
    start = profile_bytes.index(b"<?xml")
    end = profile_bytes.index(b"</plist>") + len(b"</plist>")
    return plistlib.loads(profile_bytes[start:end])


# ---------- API client ----------

class Client:
    def __init__(self) -> None:
        try:
            self.key_id = os.environ["ASC_KEY_ID"]
            self.key_pem = Path(os.environ["ASC_KEY_PATH"]).expanduser().read_bytes()
        except KeyError as missing:
            sys.exit(f"missing environment variable {missing}")
        except OSError as err:
            sys.exit(f"cannot read ASC_KEY_PATH: {err}")
        self.issuer_id = os.environ.get("ASC_ISSUER_ID", "")
        self.session = requests.Session()

    def request(self, method: str, path: str, **kwargs) -> dict:
        token = make_token(self.key_id, self.issuer_id, self.key_pem, dt.datetime.now(dt.timezone.utc))
        url = path if path.startswith("http") else f"{API}{path}"
        r = self.session.request(method, url, headers={"Authorization": f"Bearer {token}"}, timeout=60, **kwargs)
        if r.status_code >= 400:
            sys.exit(f"{method} {path} -> {r.status_code}\n{r.text}")
        return r.json() if r.content else {}

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        items, url, first = [], path, True
        while url:
            page = self.request("GET", url, params=params if first else None)
            items += page.get("data", [])
            url, first = page.get("links", {}).get("next"), False
        return items


# ---------- commands ----------

def cmd_check(c: Client, cfg: dict) -> None:
    devices = c.get_all("/devices", {"filter[platform]": "IOS", "limit": 200})
    certs = c.get_all("/certificates", {"filter[certificateType]": "DEVELOPMENT", "limit": 200})
    print(f"credentials ok: {len(devices)} iOS devices, {len(certs)} Apple Development certificates")
    for ident in (cfg["TOLLGATE_BUNDLE_ID"], cfg["TOLLGATE_TUNNEL_BUNDLE_ID"]):
        print(f"{ident}: {'exists' if find_bundle_id(c, ident) else 'missing'}")


def connected_udid() -> tuple[str, str]:
    out = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True).stdout.split()
    if len(out) != 1:
        sys.exit("connect exactly one iPhone by USB, or pass --udid and --name")
    name = subprocess.run(["ideviceinfo", "-u", out[0], "-k", "DeviceName"], capture_output=True, text=True).stdout.strip()
    return out[0], name or "iPhone"


def cmd_device(c: Client, udid: str | None, name: str | None) -> None:
    if not udid:
        udid, name = connected_udid()
    existing = c.get_all("/devices", {"filter[udid]": udid})
    if existing:
        print(f"device {udid} already registered ({existing[0]['attributes']['status']})")
        return
    c.request("POST", "/devices", json={"data": {"type": "devices", "attributes": {
        "name": name or "iPhone", "platform": "IOS", "udid": udid}}})
    print(f"registered device {udid}")


def find_bundle_id(c: Client, identifier: str) -> dict | None:
    for item in c.get_all("/bundleIds", {"filter[identifier]": identifier, "limit": 200}):
        if item["attributes"]["identifier"] == identifier:
            return item
    return None


def cmd_bundle_ids(c: Client, cfg: dict) -> None:
    for identifier, name in ((cfg["TOLLGATE_BUNDLE_ID"], "Tollgate"),
                             (cfg["TOLLGATE_TUNNEL_BUNDLE_ID"], "Tollgate Tunnel")):
        item = find_bundle_id(c, identifier)
        if not item:
            item = c.request("POST", "/bundleIds", json={"data": {"type": "bundleIds", "attributes": {
                "identifier": identifier, "name": name, "platform": "IOS"}}})["data"]
            print(f"created App ID {identifier}")
        enabled = {cap["attributes"]["capabilityType"]
                   for cap in c.get_all(f"/bundleIds/{item['id']}/bundleIdCapabilities")}
        for cap in CAPABILITIES:
            if cap in enabled:
                continue
            c.request("POST", "/bundleIdCapabilities", json={"data": {
                "type": "bundleIdCapabilities", "attributes": {"capabilityType": cap},
                "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": item["id"]}}}}})
            print(f"enabled {cap} on {identifier}")
    print(f"next: in the developer portal, assign {cfg['TOLLGATE_APP_GROUP']} to both App IDs (App Groups > Configure)")


def write_secret(path: Path, data: bytes) -> None:
    OUT.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


def load_state() -> dict:
    p = OUT / "state.json"
    return json.loads(p.read_text()) if p.exists() else {}


def cmd_cert(c: Client, force: bool = False) -> None:
    state = load_state()
    if not force and state.get("certificate_id") and (OUT / "dev-cert.p12").exists():
        live = {cert["id"] for cert in c.get_all("/certificates", {"filter[certificateType]": "DEVELOPMENT", "limit": 200})}
        if state["certificate_id"] in live:
            print(f"certificate {state['certificate_id']} already present; use `cert --force` to replace")
            return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    created = c.request("POST", "/certificates", json={"data": {"type": "certificates", "attributes": {
        "certificateType": "DEVELOPMENT", "csrContent": make_csr(key, "Tollgate CI")}}})["data"]
    cert_der = base64.b64decode(created["attributes"]["certificateContent"])
    password = secrets.token_urlsafe(24)
    write_secret(OUT / "dev-key.pem", key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_secret(OUT / "dev-cert.cer", cert_der)
    write_secret(OUT / "dev-cert.p12", make_p12(key, cert_der, password))
    write_secret(OUT / "dev-cert.password", password.encode())
    write_secret(OUT / "state.json", json.dumps({"certificate_id": created["id"]}).encode())
    print(f"created Apple Development certificate {created['id']} ({created['attributes'].get('name')})")


def cmd_profiles(c: Client, cfg: dict) -> None:
    cert_id = load_state().get("certificate_id") or sys.exit("run `cert` first")
    devices = [{"type": "devices", "id": d["id"]} for d in
               c.get_all("/devices", {"filter[platform]": "IOS", "filter[status]": "ENABLED", "limit": 200})]
    if not devices:
        sys.exit("no enabled iOS devices; run `device` first")
    team_ids = set()
    for identifier, profile_name, out_name in (
            (cfg["TOLLGATE_BUNDLE_ID"], cfg["TOLLGATE_APP_PROFILE"], "app.mobileprovision"),
            (cfg["TOLLGATE_TUNNEL_BUNDLE_ID"], cfg["TOLLGATE_TUNNEL_PROFILE"], "tunnel.mobileprovision")):
        bundle = find_bundle_id(c, identifier) or sys.exit(f"{identifier} missing; run `bundle-ids` first")
        for old in c.get_all("/profiles", {"filter[name]": profile_name}):
            if old["attributes"]["name"] == profile_name:
                c.request("DELETE", f"/profiles/{old['id']}")
        created = c.request("POST", "/profiles", json={"data": {
            "type": "profiles",
            "attributes": {"name": profile_name, "profileType": "IOS_APP_DEVELOPMENT"},
            "relationships": {
                "bundleId": {"data": {"type": "bundleIds", "id": bundle["id"]}},
                "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
                "devices": {"data": devices}}}})["data"]
        blob = base64.b64decode(created["attributes"]["profileContent"])
        write_secret(OUT / out_name, blob)
        info = profile_plist(blob)
        ents = info.get("Entitlements", {})
        team_ids.update(info.get("TeamIdentifier", []))
        ne = ents.get("com.apple.developer.networking.networkextension", [])
        groups = ents.get("com.apple.security.application-groups", [])
        print(f"{profile_name}: {len(devices)} device(s), network extensions {ne}, app groups {groups}")
        if "packet-tunnel-provider" not in ne:
            print(f"  WARNING: packet-tunnel-provider missing from {profile_name}")
        if cfg["TOLLGATE_APP_GROUP"] not in groups:
            print(f"  WARNING: {cfg['TOLLGATE_APP_GROUP']} not assigned to {identifier}; assign it in the portal and rerun `profiles`")
    if len(team_ids) != 1:
        sys.exit(f"unexpected team identifiers {team_ids}")
    write_secret(OUT / "team-id", team_ids.pop().encode())
    print("profiles written; run tooling/asc/push-secrets.sh to update the repo secrets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    dev = sub.add_parser("device")
    dev.add_argument("--udid")
    dev.add_argument("--name")
    sub.add_parser("bundle-ids")
    cert = sub.add_parser("cert")
    cert.add_argument("--force", action="store_true")
    sub.add_parser("profiles")
    sub.add_parser("setup")
    args = parser.parse_args()

    cfg = load_config(ROOT / "tooling" / "config.env")
    c = Client()
    if args.command == "check":
        cmd_check(c, cfg)
    elif args.command == "device":
        cmd_device(c, args.udid, args.name)
    elif args.command == "bundle-ids":
        cmd_bundle_ids(c, cfg)
    elif args.command == "cert":
        cmd_cert(c, args.force)
    elif args.command == "profiles":
        cmd_profiles(c, cfg)
    elif args.command == "setup":
        cmd_device(c, None, None)
        cmd_bundle_ids(c, cfg)
        cmd_cert(c)
        cmd_profiles(c, cfg)


if __name__ == "__main__":
    main()
