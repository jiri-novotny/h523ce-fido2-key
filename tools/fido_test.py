#!/usr/bin/env python3
"""End-to-end test of the STM32H523 FIDO2 authenticator.

User presence is simulated by bumping the firmware's debounced press counters
(OK: press_count, Next: next_count) through the OpenOCD TCL port, so the test runs
without touching the buttons.
"""
import hashlib
import os
import socket
import struct
import sys
import time

from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1, ApduError
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.attestation import PackedAttestation, AttestationType
from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

PRESS_ADDR = int(sys.argv[1], 16)
NEXT_ADDR = int(sys.argv[2], 16)
PIN = "1234"
NEW_PIN = "98765"
RP = {"id": "example.com", "name": "Example"}

failures = []


class Ocd:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", 6666))

    def cmd(self, c):
        self.s.sendall(c.encode() + b"\x1a")
        buf = b""
        while not buf.endswith(b"\x1a"):
            buf += self.s.recv(4096)
        return buf[:-1].decode()

    def press(self, addr=PRESS_ADDR):
        # read_memory returns "0x.." list
        v = int(self.cmd(f"read_memory 0x{addr:08x} 32 1").split()[0], 0)
        self.cmd(f"write_memory 0x{addr:08x} 32 {{{v + 1}}}")


ocd = Ocd()


def keepalive(status):
    if status == 2:  # UPNEEDED
        time.sleep(0.2)
        ocd.press()


def buttons(seq):
    """keepalive that presses seq ("n" = Next, "o" = OK) once the key waits"""
    done = []

    def ka(status):
        if status == 2 and not done:
            done.append(True)
            for b in seq:
                time.sleep(0.2)
                ocd.press(NEXT_ADDR if b == "n" else PRESS_ADDR)
    return ka


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    if not cond:
        failures.append(name)


def expect_err(name, code, fn):
    try:
        fn()
        check(name, False, "no error")
    except CtapError as e:
        check(name, e.code == code, f"got {e.code!r}")


def find_dev():
    for d in CtapHidDevice.list_devices():
        if d.descriptor.vid == 0xCAFE:
            return d
    raise SystemExit("device not found")


def cdh():
    return os.urandom(32)


dev = find_dev()
print("device:", dev.descriptor.product_name, dev.descriptor.serial_number)

# --- CTAPHID ---
data = os.urandom(1000)
check("ctaphid ping 1000 B", dev.ping(data) == data)
dev.wink()
check("ctaphid wink", True)

ctap = Ctap2(dev)
info = ctap.info
print("versions", info.versions, "ext", info.extensions, "options", dict(info.options))
check("getInfo versions", "FIDO_2_1" in info.versions and "U2F_V2" in info.versions)

# --- reset first, while inside the 10 s window is not guaranteed: done at the end ---

# --- makeCredential ES256 ---
h = cdh()
t = time.time()
att = ctap.make_credential(h, RP, {"id": b"user1", "name": "u1"}, [{"type": "public-key", "alg": -7}],
                           on_keepalive=keepalive)
print(f"  makeCredential took {time.time() - t:.2f} s (incl. simulated touch)")
res = PackedAttestation().verify(att.att_stmt, att.auth_data, h)
check("MC ES256 packed self attestation", res.attestation_type == AttestationType.SELF)
cd = att.auth_data.credential_data
check("MC ES256 flags UP|AT", att.auth_data.flags & 0x41 == 0x41)
check("MC aaguid", cd.aaguid != bytes(16))
pk_es = cd.public_key
cid_es = cd.credential_id

# --- getAssertion ES256 ---
h = cdh()
t = time.time()
a = ctap.get_assertion(RP["id"], h, [{"type": "public-key", "id": cid_es}], on_keepalive=keepalive)
print(f"  getAssertion took {time.time() - t:.2f} s")
a.verify(h, pk_es)
check("GA ES256 signature", True)
c1 = a.auth_data.counter
a2 = ctap.get_assertion(RP["id"], h, [{"type": "public-key", "id": cid_es}], on_keepalive=keepalive)
check("GA counter increments", a2.auth_data.counter > c1)

# --- silent (up=false) ---
a = ctap.get_assertion(RP["id"], h, [{"type": "public-key", "id": cid_es}], options={"up": False})
a.verify(h, pk_es)
check("GA up=false no UP flag", a.auth_data.flags & 0x01 == 0)

# --- wrong RP / unknown cred ---
expect_err("GA wrong rp -> NO_CREDENTIALS", CtapError.ERR.NO_CREDENTIALS,
           lambda: ctap.get_assertion("other.com", h, [{"type": "public-key", "id": cid_es}],
                                      options={"up": False}))
expect_err("GA no rk -> NO_CREDENTIALS", CtapError.ERR.NO_CREDENTIALS,
           lambda: ctap.get_assertion(RP["id"], h, options={"up": False}))

# --- excludeList ---
expect_err("MC excludeList -> CREDENTIAL_EXCLUDED", CtapError.ERR.CREDENTIAL_EXCLUDED,
           lambda: ctap.make_credential(cdh(), RP, {"id": b"user1"}, [{"type": "public-key", "alg": -7}],
                                        exclude_list=[{"type": "public-key", "id": cid_es}],
                                        on_keepalive=keepalive))

# --- EdDSA ---
h = cdh()
att = ctap.make_credential(h, RP, {"id": b"user2"}, [{"type": "public-key", "alg": -8}],
                           on_keepalive=keepalive)
PackedAttestation().verify(att.att_stmt, att.auth_data, h)
check("MC EdDSA attestation", att.auth_data.credential_data.public_key.ALGORITHM == -8)
pk_ed = att.auth_data.credential_data.public_key
cid_ed = att.auth_data.credential_data.credential_id
a = ctap.get_assertion(RP["id"], h, [{"type": "public-key", "id": cid_ed}], on_keepalive=keepalive)
a.verify(h, pk_ed)
check("GA EdDSA signature", True)
expect_err("MC unsupported alg", CtapError.ERR.UNSUPPORTED_ALGORITHM,
           lambda: ctap.make_credential(cdh(), RP, {"id": b"x"}, [{"type": "public-key", "alg": -257}]))

# --- U2F ---
ctap1 = Ctap1(dev)
check("U2F version", ctap1.get_version() == "U2F_V2")
app = hashlib.sha256(b"u2f.example.com").digest()
chal = os.urandom(32)


def u2f_retry(fn):
    pressed = False
    for _ in range(50):
        try:
            return fn()
        except ApduError as e:
            if e.code != 0x6985:
                raise
            if not pressed:
                ocd.press()
                pressed = True
            time.sleep(0.2)
    raise RuntimeError("U2F timeout")


reg = u2f_retry(lambda: ctap1.register(chal, app))
reg.verify(app, chal)
check("U2F register + attestation cert signature", True)
sig = u2f_retry(lambda: ctap1.authenticate(chal, app, reg.key_handle))
sig.verify(app, chal, reg.public_key)
check("U2F authenticate", True)
try:
    ctap1.authenticate(chal, app, reg.key_handle, check_only=True)
except ApduError as e:
    check("U2F check-only -> 6985", e.code == 0x6985)
try:
    ctap1.authenticate(chal, os.urandom(32), reg.key_handle, check_only=True)
except ApduError as e:
    check("U2F wrong app -> 6A80", e.code == 0x6A80)
# CTAP2 assertion with U2F credential
from fido2.cose import ES256
a = ctap.get_assertion("u2f.example.com", h, [{"type": "public-key", "id": reg.key_handle}],
                       options={"up": False})
check("CTAP2 GA with U2F key handle", a.credential["id"] == reg.key_handle)

# --- clientPIN ---
for proto_cls in (PinProtocolV2,):
    cp = ClientPin(ctap, proto_cls())
    if not ctap.get_info().options.get("clientPin"):
        cp.set_pin(PIN)
    check("clientPin set", ctap.get_info().options.get("clientPin") is True)
    check("pin retries 8", cp.get_pin_retries()[0] == 8)
    expect_err("wrong PIN -> PIN_INVALID", CtapError.ERR.PIN_INVALID, lambda: cp.get_pin_token("0000"))
    check("pin retries 7", cp.get_pin_retries()[0] == 7)
    cp.get_pin_token(PIN)
    check("pin retries reset", cp.get_pin_retries()[0] == 8)

expect_err("MC rk without PIN -> PUAT_REQUIRED", CtapError.ERR.PUAT_REQUIRED,
           lambda: ctap.make_credential(cdh(), RP, {"id": b"rk"}, [{"type": "public-key", "alg": -7}],
                                        options={"rk": True}))

rk_ids = []
for proto_cls in (PinProtocolV1, PinProtocolV2):
    proto = proto_cls()
    cp = ClientPin(ctap, proto)
    token = cp.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
    h = cdh()
    uid = b"rk-user-%d" % proto.VERSION
    att = ctap.make_credential(h, RP, {"id": uid, "name": f"alice{proto.VERSION}", "displayName": "Alice"},
                               [{"type": "public-key", "alg": -7}], options={"rk": True},
                               pin_uv_param=proto.authenticate(token, h), pin_uv_protocol=proto.VERSION,
                               on_keepalive=keepalive)
    check(f"MC rk with PIN proto {proto.VERSION} UV flag", att.auth_data.flags & 0x04 != 0)
    rk_ids.append((uid, att.auth_data.credential_data.credential_id, att.auth_data.credential_data.public_key))

# discoverable assertion with UV and UP: the account is picked on the display, Next moves to the older one
proto = PinProtocolV2()
cp = ClientPin(ctap, proto)
token = cp.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, RP["id"])
h = cdh()
res = ctap.get_assertions(RP["id"], h, pin_uv_param=proto.authenticate(token, h), pin_uv_protocol=2,
                          on_keepalive=buttons("no"))
check("GA rk picked on the key: one response", len(res) == 1 and res[0].number_of_credentials is None, f"{len(res)}")
check("GA rk picked on the key: userSelected", res[0].user_selected is True)
check("GA rk picked on the key: second account", res[0].user["id"] == rk_ids[0][0])
res[0].verify(h, rk_ids[0][2])
h = cdh()
expect_err("GA rk cancel entry -> OPERATION_DENIED", CtapError.ERR.OPERATION_DENIED,
           lambda: ctap.get_assertion(RP["id"], h, pin_uv_param=proto.authenticate(token, h), pin_uv_protocol=2,
                                      on_keepalive=buttons("nno")))
expect_err("MC Next -> OPERATION_DENIED", CtapError.ERR.OPERATION_DENIED,
           lambda: ctap.make_credential(cdh(), RP, {"id": b"x", "name": "x"}, [{"type": "public-key", "alg": -7}],
                                        on_keepalive=buttons("n")))
# without UP nothing is shown: all of them, newest first
h = cdh()
res = ctap.get_assertions(RP["id"], h, pin_uv_param=proto.authenticate(token, h), pin_uv_protocol=2,
                          options={"up": False})
check("GA rk count 2 + getNext", len(res) == 2, f"{len(res)}")
check("GA rk newest first", res[0].user["id"] == rk_ids[1][0])
check("GA rk user name with UV", res[0].user.get("name") == "alice2")
for r in res:
    pk = [x[2] for x in rk_ids if x[1] == r.credential["id"]][0]
    r.verify(h, pk)
check("GA rk signatures", True)
# without UV: user id only
res = ctap.get_assertions(RP["id"], h, options={"up": False})
check("GA rk without UV hides name", "name" not in res[0].user and res[0].user["id"])

# --- credential management ---
token = cp.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
cm = CredentialManagement(ctap, proto, token)
meta = cm.get_metadata()
check("credMgmt metadata", meta[1] == 2, str(meta))
rps = cm.enumerate_rps()
check("credMgmt enumerate RPs", len(rps) == 1 and rps[0][3]["id"] == RP["id"])
creds = cm.enumerate_creds(hashlib.sha256(RP["id"].encode()).digest())
check("credMgmt enumerate creds", len(creds) == 2)
cm.update_user_info({"type": "public-key", "id": rk_ids[0][1]},
                    {"id": rk_ids[0][0], "name": "renamed", "displayName": "Renamed"})
creds = cm.enumerate_creds(hashlib.sha256(RP["id"].encode()).digest())
check("credMgmt update user", any(c[6].get("name") == "renamed" for c in creds))
cm.delete_cred({"type": "public-key", "id": rk_ids[0][1]})
check("credMgmt delete", cm.get_metadata()[1] == 1)

# --- hmac-secret / PRF through the WebAuthn client ---
class UI(UserInteraction):
    def prompt_up(self):
        time.sleep(0.2)
        ocd.press()

    def request_pin(self, permissions, rp_id):
        return PIN

    def request_uv(self, permissions, rp_id):
        return True


client = Fido2Client(dev, DefaultClientDataCollector("https://example.com"), user_interaction=UI())
server = Fido2Server(PublicKeyCredentialRpEntity(name="Example", id="example.com"))
user = PublicKeyCredentialUserEntity(name="bob", id=b"bob-id", display_name="Bob")
opts, state = server.register_begin(user, resident_key_requirement="required", user_verification="required")
o = dict(opts.public_key)
o["extensions"] = {"prf": {}}
reg = client.make_credential(o)
auth = server.register_complete(state, reg)
check("WebAuthn register (rk, UV) via Fido2Client", True)
check("PRF enabled", reg.client_extension_results.get("prf", {}).get("enabled") is True)
salt = os.urandom(32)
outs = []
for s in (salt, salt, os.urandom(32)):
    req, st = server.authenticate_begin(user_verification="required")
    ro = dict(req.public_key)
    ro["extensions"] = {"prf": {"eval": {"first": s}}}
    sel = client.get_assertion(ro)
    resp = sel.get_response(0)
    server.authenticate_complete(st, [auth.credential_data], resp)
    outs.append(resp.client_extension_results["prf"]["results"]["first"])
check("WebAuthn authenticate via Fido2Client", True)
check("PRF deterministic", outs[0] == outs[1] and len(outs[0]) == 43)
check("PRF salt dependent", outs[0] != outs[2])

# --- changePIN ---
cp = ClientPin(ctap, PinProtocolV2())
cp.change_pin(PIN, NEW_PIN)
cp.get_pin_token(NEW_PIN)
check("changePIN", True)

# --- reset: power-up window ---
expect_err("reset after 10 s -> NOT_ALLOWED", CtapError.ERR.NOT_ALLOWED, lambda: ctap.reset())
ocd.cmd("reset run")
dev.close()
time.sleep(2.5)
dev = find_dev()
ctap = Ctap2(dev)
ctap.reset(on_keepalive=keepalive)
info = ctap.get_info()
check("reset clears PIN", info.options.get("clientPin") is False)
expect_err("reset invalidates credentials", CtapError.ERR.NO_CREDENTIALS,
           lambda: ctap.get_assertion(RP["id"], cdh(), [{"type": "public-key", "id": cid_es}],
                                      options={"up": False}))
check("reset removes rk", info.remaining_disc_creds == 64, str(info.remaining_disc_creds))

print()
print("ALL PASSED" if not failures else f"{len(failures)} FAILED: {failures}")
sys.exit(1 if failures else 0)
