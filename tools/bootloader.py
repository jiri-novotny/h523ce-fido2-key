#!/usr/bin/env python3
"""Reset the STM32H523 FIDO2 key into its bootloader (Linux, hidraw).

Sends the vendor CTAPHID command 0x50; the key blinks and waits for a button
touch, then re-enumerates as cafe:8009 (USB DFU, signed images only):

    dfu-util -d cafe:8009 -D build/app/stm32h523-fido2-signed.bin

The bootloader then shows the version on the display and waits for another touch before it
installs the image.
"""
import glob
import os
import select
import struct
import sys

VID = 0xCAFE
CID_BROADCAST = 0xFFFFFFFF
CMD_INIT = 0x86
CMD_KEEPALIVE = 0xBB
CMD_ERROR = 0xBF
CMD_BOOTLOADER = 0xD0  # 0x50 | TYPE_INIT


def find_device():
    for node in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            uevent = open(os.path.join(node, "device/uevent")).read()
            desc = open(os.path.join(node, "device/report_descriptor"), "rb").read()
        except OSError:
            continue
        if f":0000{VID:04X}:" in uevent and desc.startswith(b"\x06\xd0\xf1"):
            return "/dev/" + os.path.basename(node)
    return None


def send(fd, cid, cmd, data=b""):
    pkt = struct.pack(">IBH", cid, cmd, len(data)) + data
    os.write(fd, b"\x00" + pkt.ljust(64, b"\x00"))  # leading report ID 0


def recv(fd, cid, timeout):
    while True:
        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            raise TimeoutError("no response")
        pkt = os.read(fd, 64)
        rcid, cmd, n = struct.unpack(">IBH", pkt[:7])
        if rcid != cid:
            continue
        if cmd == CMD_KEEPALIVE:
            continue
        return cmd, pkt[7 : 7 + n]


def main():
    path = find_device()
    if path is None:
        sys.exit("FIDO2 key not found")
    fd = os.open(path, os.O_RDWR)

    nonce = os.urandom(8)
    send(fd, CID_BROADCAST, CMD_INIT, nonce)
    cmd, data = recv(fd, CID_BROADCAST, 2)
    if cmd != CMD_INIT or data[:8] != nonce:
        sys.exit("CTAPHID_INIT failed")
    cid = struct.unpack(">I", data[8:12])[0]

    print("touch the button to enter the bootloader ...")
    send(fd, cid, CMD_BOOTLOADER)
    cmd, data = recv(fd, cid, 35)
    if cmd == CMD_ERROR:
        sys.exit(f"CTAPHID error 0x{data[0]:02x} (old firmware?)")
    if data[:1] != b"\x00":
        sys.exit(f"refused, status 0x{data[0]:02x} (0x2f = timeout)")
    print("rebooting into the bootloader (cafe:8009)")


if __name__ == "__main__":
    main()
