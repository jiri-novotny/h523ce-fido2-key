# h523ce-fido2

FIDO2 / U2F authenticator firmware for the STM32H523CE (WeAct board). Everything is stored in the
MCU's internal flash; there is no external memory.

The `feat/external-flash` branch keeps the earlier variant with littlefs on a GD25Q128 SPI NOR
flash, for when far more than 64 discoverable credentials are needed. It needs rollback
protection for the external chip (epoch, credential list), which this variant doesn't.

## Using the key

The key is a USB FIDO2 security key (CTAP 2.1 and U2F). Browsers, operating systems and tools
that support security keys or passkeys work with it without drivers. It has no fingerprint
sensor: you confirm a request with the **OK** button, and the key checks the PIN when a site asks
for user verification. See [Buttons](#buttons) and [Display](#display) for the hardware.

| | |
|---|---|
| Passkeys (discoverable credentials) | up to 64; non-discoverable credentials are unlimited |
| Algorithms | ES256 (P-256), EdDSA (Ed25519) |
| Extensions | `hmac-secret`, `credProtect` |
| PIN | at least 4 characters, at most 63 bytes; 8 wrong tries in total lock the key until a reset |
| Credential management | yes (list and delete passkeys) |

### Plugging it in

The LED flashes once a second while the key is idle, and the display (if fitted) shows the key's
name for 3 s. The key enumerates as `cafe:8008`, "k4chn1k key".

On Linux, browsers need access to the key's `/dev/hidraw*` node. systemd (version 244 and newer)
recognises FIDO keys by their HID descriptor and grants access to the logged-in user. On older
systems, add a udev rule, e.g. `/etc/udev/rules.d/70-fido-k4chn1k.rules`:

```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="8008", TAG+="uaccess"
```

then run `sudo udevadm control --reload && sudo udevadm trigger`.

### Confirming a request

Whenever a site or tool asks the key to do something, the LED blinks fast and the display says
what is being confirmed: the site and the account. **Check the site name before you press OK.**
The key shows the domain it will sign for; a look-alike domain shows as such.

- **OK** confirms. **Next** declines at once. Without a press, the request times out after 30 s.
- If you have several passkeys for the same site, the key shows them one by one
  (`Sign in to  1/3`). Next moves to the next account, OK signs in with the one shown.

### Setting a PIN

Set a PIN before first use. Sites that ask for user verification, and most passkey sign-ins,
can't use the key without one.

- **Chrome / Edge:** Settings → Privacy and security → Security → Manage security keys →
  Create a PIN.
- **Windows:** Settings → Accounts → Sign-in options → Security key → Manage.
- **macOS / Firefox:** Firefox settings → Privacy & Security → Security keys (or use Chrome).
- **Command line** (libfido2, package `fido2-tools`):

  ```sh
  fido2-token -L                  # find the device, e.g. /dev/hidraw3
  fido2-token -S /dev/hidraw3     # set a PIN
  fido2-token -C /dev/hidraw3     # change it
  ```

After 3 wrong PINs in a row, unplug and replug the key before you try again. After **8** wrong
PINs in total, the key is locked and only a [reset](#resetting-the-key) makes it usable again.
A correct PIN starts the count again.

### Registering and signing in on websites

On a site's security settings, choose "Add security key" or "Create a passkey" and pick a
security key / USB key when the browser asks. Press OK when the display shows `Register at` or
`Save passkey for`. To sign in, insert the key, enter the PIN if asked, and press OK on
`Sign in to`.

- A **passkey** is stored on the key and lets you sign in without typing a username. The key
  holds up to 64 of them.
- A **security key used as a second factor** isn't stored on the key; the site keeps the
  credential ID. There's no limit on these.
- Sites that still use the old U2F API work too. The display shows `U2F: site not shown`,
  because U2F only gives the key a hash of the site, so check the address bar instead.

### Managing passkeys

- **Chrome / Edge:** Manage security keys → Sign-in data: lists and deletes passkeys.
- **Command line:**

  ```sh
  fido2-token -I /dev/hidraw3              # info: versions, options, PIN retries left
  fido2-token -L -r /dev/hidraw3           # sites with passkeys
  fido2-token -L -k example.com /dev/hidraw3   # passkeys for one site
  fido2-token -D -i <credential id> /dev/hidraw3
  ```

### SSH

OpenSSH 8.2 and newer use the key directly:

```sh
ssh-keygen -t ed25519-sk                          # key file on disk, needs the security key to use
ssh-keygen -t ed25519-sk -O resident -O verify-required   # stored on the key, asks for PIN
ssh-keygen -K                                     # on a new machine: get resident keys back
```

Add the `.pub` file to `~/.ssh/authorized_keys` on the server as usual. Each login asks for a
press of OK. Use `-t ecdsa-sk` for servers that don't accept Ed25519.

### Unlocking an encrypted disk (Linux)

The `hmac-secret` extension lets the key unlock a LUKS volume:

```sh
sudo systemd-cryptenroll --fido2-device=auto /dev/nvme0n1p3
```

Then add `fido2-device=auto` to the volume's options in `/etc/crypttab`. Keep a password or
recovery key slot as well: if the key is lost or reset, the disk can't be unlocked with it any
more.

### Resetting the key

A reset deletes all passkeys and the PIN and makes every credential the key has ever created
unusable, including those registered as a second factor. Sites will no longer accept the key.

The reset is allowed only within **10 s of plugging the key in**, and needs a press of OK on
`Reset this key?`:

- **Chrome / Edge:** Manage security keys → Reset your security key, then replug the key when
  asked.
- **Command line:** replug the key and within 10 s run `fido2-token -R /dev/hidraw3`.

### Updating the firmware

Updates keep all passkeys and the PIN. See [Updating over USB](#updating-over-usb): the key asks
for a press of OK before it restarts into the bootloader, and the bootloader asks again before it
installs the new version.

### If you lose the key

On a Closed device (see [Provisioning](#provisioning-and-closing-a-device)) nothing on the key can
be read out, but anyone who has it can try PINs (8 tries) and use credentials that don't need a
PIN. Register a second key or another sign-in method on every
important account, and remove the lost key from your accounts.

## Device key and storage encryption

Every record the authenticator stores is encrypted and authenticated with a per-device key. The
key is generated on the device and kept in the MCU's option byte keys (OBK). It is never written
to the data area, and the firmware doesn't hand it to anything outside the record store.

### Key hierarchy

```
OBK HDPL2 area (internal, per device)
└── device key (32 B, RNG)                  drivers/obk.c
    └── encrypts every record               app/kv.c
        └── state record holds the master secret (32 B, RNG, new on CTAP reset)
            ├── credential keys (cred mac, cred priv, hmac-secret, attestation)   app/cred.c
            └── record name key ("rk name")                                       app/store.c
```

The device key belongs to the hardware and doesn't change. The master secret belongs to the
FIDO identity: `authenticatorReset` replaces it, which invalidates all credentials, but the device
key stays the same.

### Boot flow

```
reset ─ bootloader (btl/) at HDPL1     owns OBK HDPL1: anti-rollback counter
          verifies the signed app, raises the HDPL to 2, jumps
        app (main.c) at HDPL2           owns OBK HDPL2: device key
          loads the key, raises the HDPL to 3
```

With TrustZone disabled the device starts at HDPL1 (measured: `SBS->HDPLSR = 0x51`). Each stage
raises the HDPL before handing over, and the HDPL only goes back down on reset, so a stage can't
read or change the OBK area of the stage before it. See
[Bootloader and signed updates](#bootloader-and-signed-updates) for the bootloader.

The app's `main()` runs these steps in order:

1. `HAL_Init()`, clocks, watchdog, GPIO, `rng_init()`.
2. **`obk_load_key()`**:
   - Checks that the HDPL is 2, i.e. the app was started by the bootloader.
   - Looks for a valid key slot and generates one if none exists (see below).
   - Copies the key to the caller, then increments the HDPL to 3. It increments even if no key
     was found. Until the next reset, the OBK HDPL2 area is unreadable from this point on.
3. **`kv_init(device_key)`**: `kv.c` keeps its own copy and scans the record store, and `main()`
   wipes the local copy.
4. `store_init()` reads the state record and derives the credential keys and the record name key
   from the master secret. On a blank data area it creates a new state.

If `obk_load_key()` fails, `main()` calls `Error_Handler()` and the device does not start.

### No jump to the ROM bootloader

The firmware can't start the ST system bootloader; there is no CTAPHID command or software jump
for it. The reasons:

- On the STM32H523 with TrustZone disabled, BOOT0 starts the system bootloader only in the Open
  state. In Provisioned, Closed and Locked, the device always boots from `NSBOOTADD` (RM0481
  Table 25, AN2606 Pattern 17). Neither document says whether a software jump still works in
  Closed, so updates can't rely on it.
- The bootloader can change the product state and provision OBK data at HDPL1 (AN2606
  Table 116), so the firmware shouldn't give it a way in.

Firmware updates go through our own bootloader instead, see
[Bootloader and signed updates](#bootloader-and-signed-updates). On a development board in Open
state, the ROM bootloader can still be started with BOOT0 held high during reset.

### Key generation (first boot)

The key lives in the HDPL2 OBK area (`FLASH_OBK_HDPL2_BASE_NS` = 0x0BFD0900, 768 bytes, RM0481
Table 58: "uRoT, OS or secure application"), as 16 slots of 48 bytes:

| Offset | Size | Content                               |
|-------:|-----:|---------------------------------------|
| 0      | 32   | device key                            |
| 32     | 4    | magic `0x44564B31` ("DVK1")           |
| 36     | 4    | `~magic`                              |
| 40     | 8    | reserved, `0xFF`                      |

`obk_load_key()` scans the slots in order:

- **Valid slot** (magic and `~magic` match): its key is used.
- **Blank slot** (all `0xFF`): 32 bytes come from the hardware RNG and the slot is written as three
  128-bit quad-words, key first and the commit word last. The firmware programs it directly into
  the current OBK sector, so the alternate-sector swap procedure is never used.
- **Partially written slot** (power lost during provisioning): it can't be reprogrammed, so it is
  skipped and the next blank slot is used.
- **Provisioning fails before anything is written** (RNG or flash error): `obk_load_key()` fails
  and the device stops in `Error_Handler()`; the next reset tries the same slot again. Moving on
  to the next slot would give a different key at the next boot, which would lose all records.
- **Every slot reads zero** (after a tamper event the OBK reads as zero, RM0481 Tables 77/78):
  no slot is blank or valid, so `obk_load_key()` fails and the device stops in
  `Error_Handler()`. It does not generate a new key.

Generation happens once per chip. Firmware updates and both flash erase types leave the key in
place.

### Data area

The last 96 KB of internal flash (`BOOT_DATA_BASE` = 0x08068000, bank 2) hold the app's data. The
bootloader never erases them: the update slot ends before them and longer images are refused. In
the Closed state nothing but the signed app can write them, so nothing can be rolled back or
restored from an old copy.

| Address      | Size  | Content | Code |
|--------------|-------|---------|------|
| `0x08068000` | 64 KB | records: state (master secret, PIN hash, settings) and discoverable credentials | `app/kv.c` |
| `0x08078000` | 32 KB | PIN retries and signature counter, written often | `app/nv.c` |

Both parts go through `app/iflash.c`. A quad-word cut off in the middle of programming can read
with an ECC double error; the NMI is ignored while `iflash.c` reads and the read reports a
failure, so the quad-word counts as dead.

**Records** (`kv.c`): 128 slots of 512 bytes, 16 per 8 KB sector. A slot holds a header quad-word
(magic, 8-byte key, sequence number), the encrypted record and a tombstone quad-word at the end:

```
header[16] | nonce[24] | mac[16] | ciphertext[424] | unused | tombstone[16]
```

- The cipher is XChaCha20-Poly1305 (monocypher `crypto_aead_lock`), keyed with the device key.
  Each write takes a fresh 24-byte nonce from the RNG. The associated data is the record key and
  sequence number, so a record copied to another key fails to decrypt.
- A write programs the record first and the header last, then marks the old copy with its
  tombstone. A power loss keeps the old or the new copy; if both survive, `kv_init()` keeps the
  one with the higher sequence number.
- When no more than 16 slots are blank, a sector without live records is erased, or the live
  records of the sector with the most dead slots are copied elsewhere and the sector is erased.
  The 16 blank slots are kept for these copies.
- Discoverable credentials are keyed by the first 8 bytes of
  `HMAC-SHA256(name key, rpIdHash || userId)`, so the keys don't show which accounts are stored.
  Up to 64 (`STORE_RK_MAX`) fit, each record 412 bytes.
- `authenticatorReset` erases the record area and creates a new state.

**PIN retries and signature counter** (`nv.c`): a ring of four 8 KB sectors, each with a header
(sequence number) and 511 records of 16 bytes; a full sector moves on to the next one. The PIN
retry counter is decremented before every PIN check, and the signature counter never goes back,
not even on `authenticatorReset`.

**Wear**: internal flash takes 10 k erase cycles per sector.
- Signatures and PIN checks go to `nv.c`: a signature or a wrong PIN costs one record, a right
  PIN two. That's about 20 million writes before the ring wears out.
- Credentials and state changes go to `kv.c`. With all 64 credentials stored, an erase frees
  roughly 5 to 15 slots, and the erases rotate over the 8 sectors: several hundred thousand
  writes, i.e. well over 100 000 registrations (two writes each). Fewer stored credentials leave
  more dead slots per erase.

A chip erase over SWD erases the data area too, and the device starts with a new state at the
next boot. Flashing the hex files over SWD or updating over USB doesn't touch it.

### What is protected

| Attack                                                            | Protected | Notes |
|-------------------------------------------------------------------|-----------|-------|
| Installing firmware not signed with our key                       | yes | the bootloader checks the signature before erasing and on every boot (tested) |
| Installing an older signed firmware (downgrade)                   | yes | anti-rollback counter in OBK HDPL1, refused before erasing (tested) |
| Reading the firmware back over USB                                | yes | the bootloader's DFU has no upload (tested) |
| Reading or restoring stored data                                  | yes | internal flash: no debug access in the Closed state, no USB readback, the bootloader never touches the data area |
| Firmware after boot (e.g. a CTAP parser bug) reading the device key | partly | the OBK copy is hidden at HDPL3, but a bug that can read arbitrary memory can still read the RAM copy in `kv.c` |
| ROM DFU bootloader reading OBK                                    | yes | the firmware can't start it; on Open boards (BOOT0) it refuses OBK addresses (tested) |
| Debugger in **OPEN** product state                                | **no** | a read under reset (HDPL1) returns zeros for the key area, but a debugger can halt the app at HDPL2 before `obk_load_key()` and read it |
| Fault injection or glitching                                      | no | not in scope |

## Buttons

| Button | Pins | Meaning |
|---|---|---|
| OK | PB10, or PA0 on the board | confirm, pick the account shown |
| Next | PC14 | decline; in a list the next item |

All are wired to GND, with the internal pull-ups. PC14 is OSC32_IN; the LSE is not used.
Without the Next button every prompt still works with OK alone, declining by timeout.

- **Simple prompt:** OK confirms, Next declines: CTAP2 returns `CTAP2_ERR_OPERATION_DENIED` at
  once instead of waiting for the 30 s timeout. U2F has no way to decline; the prompt goes
  away and the host's polls stay unsatisfied until it gives up.
- **Sign-in with several passkeys for the site** (no allowList, UP requested): the key shows
  them one by one, `Sign in to  2/3` with the account, newest first. Next steps to the next
  account and, after the last, to `Cancel sign-in?`; OK picks. Only the picked credential is
  returned, with `userSelected` and without `numberOfCredentials` (CTAP 2.1 §6.2.2, authenticator
  with a display), so the platform doesn't show its own account list. With `up: false` nothing
  is shown and all of them come through `getNextAssertion` as before.
- **Bootloader:** OK installs the image shown, Next refuses it at once.

## Display

An optional SSD1306 128x32 OLED on I2C1 (PB6 SCL, PB7 SDA, 3.3 V; the module has the pull-ups)
shows what a button press confirms. Driver: `drivers/display.c`, X11 5x7 font (public domain)
in `drivers/font5x7.h`. Without a display everything works as before.

The app (`app/up.c`) sets a prompt before every wait for the button and blanks the screen when
the wait ends; an OLED left on one picture burns in. The bottom line says what the buttons do,
`OK: confirm  Next: cancel` by default, see [Buttons](#buttons).

| Request | Prompt |
|---|---|
| makeCredential | `Register at` / `Save passkey for` (discoverable), site, account |
| getAssertion | `Sign in to`, site, the account; with several, `Sign in to  1/N` to pick one |
| excluded credential | `Already registered at`, site, account |
| authenticatorReset | `Reset this key?` |
| selection | `Select this key?` |
| U2F | `Register at` / `Sign in to`, `U2F: site not shown` (U2F only has a hash) |
| vendor 0x50 | `Firmware update?` |

- **Site:** the rpId the key signs for, ASCII only, any other byte as `?` so a look-alike domain
  can't pass. When too long, the start is cut: the end of an rpId decides the domain.
- **Account:** name, else displayName. Accented Latin letters lose the accent.
- At power-up the name of the key shows for 3 s, a wink shows `Hello!`.

The bootloader shows its own screens in DFU mode and asks for the button before installing,
see [Updating over USB](#updating-over-usb).

## Bootloader and signed updates

The bootloader (`btl/`, built with the `btl` VS Code configuration or `-Dbtl=1`) is the first
code after reset. It only starts an app that is signed with the firmware signing key and not
older than the last installed version, and it takes updates over USB DFU. It has no secrets of
its own: it holds the public half of the signing key.

### Flash layout (`drivers/boot.h`)

| Address      | Size    | Content |
|--------------|---------|---------|
| `0x08000000` | 32 KB   | bootloader, write-protected in production |
| `0x08008000` | 1 KB    | image header (`boot_hdr_t`), padded |
| `0x08008400` | 383 KB  | app (`VECT_TAB_OFFSET = 0x8400`) |
| `0x08068000` | 96 KB   | app data, see [Data area](#data-area) |

The first 16 bytes of SRAM are outside both linker scripts' RAM. The app writes
`BOOT_REQUEST_MAGIC` there to ask the bootloader to stay in DFU mode after a reset.

### Image header and signature

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 4    | magic `0x4B464942` |
| 4      | 4    | header version (1) |
| 8      | 4    | firmware version, for anti-rollback |
| 12     | 4    | image size (multiple of 16) |
| 16     | 32   | SHA-256 of the image |
| 48     | 16   | reserved, `0xFF` |
| 64     | 64   | ECDSA P-256 signature r ‖ s over bytes 0..63 |

The signature covers the header, and the header covers the image through its hash. The
bootloader computes SHA-256 with the HASH peripheral and verifies ECDSA with the PKA, which runs
in limited mode on the STM32H523 (verification only, RM0481 §41.3). There is no ECC code in software.

### Boot

1. If the app asked for the bootloader (`BOOT_REQUEST`) or OK is held at reset, it enters DFU
   mode.
2. Otherwise it checks the header (format, version against the rollback counter, signature) and
   the image hash. If anything fails, it enters DFU mode.
3. If everything passes: peripherals and clocks back to reset state, HDPL raised to 2, jump to
   the app.

In DFU mode the LED blinks slowly (250 ms) and the device enumerates as `cafe:8009`.

### Updating over USB

```sh
python3 tools/bootloader.py          # running app: CTAPHID vendor command 0x50, touch to confirm
dfu-util -d cafe:8009 -D build/app/stm32h523-fido2-signed.bin
```

The VS Code tasks "Bootloader" and "Update" run these two commands. `dfu-util` then waits until
the update is confirmed on the device.

In DFU mode the display (if connected, see [Display](#display)) shows the installed version, the
oldest version still allowed and "Waiting for update".

- **Block 0** carries the header. The bootloader checks it, including the signature and the
  rollback counter, **before** erasing anything. A wrongly signed image or a downgrade leaves
  the installed app untouched (`dfuERROR`, status `errFILE`), and the display says which.
- **Confirmation:** a valid block 0 stays busy (`dfuDNBUSY`; the host keeps polling) while the
  display shows `Install vN?` with the installed version. A new press of OK continues the
  update; a button held since reset doesn't count. Next, or no press within 30 s, refuses the
  update (status `errVENDOR`) and nothing is erased. Without a display the press is still
  needed; the LED blinks fast meanwhile. Any other download or manifest request from the host
  while the prompt is shown cancels it, so the press only ever installs the header shown.
- **Following blocks** are written into the slot, erasing 8 KB sectors as needed. The display
  shows the progress in steps of 10 %.
- **Manifestation:** the bootloader checks the image hash. If it matches, it raises the rollback
  counter to the new version and resets into the app after 2.5 s. If not, it reports `errVERIFY`
  and stays in DFU, because the old app is already partly overwritten. Flashing a good image
  recovers it.
- There's no upload (read back) and no write outside the slot.

### Anti-rollback

The bootloader keeps the lowest allowed version as append-only 16-byte records in the HDPL1 OBK
area, from 0x0BFD0200. The first 256 bytes of that area are left free for the ST debug
authentication data (RM0481 §66.2.7). The app runs at HDPL2 and can't change the records. There
are 112 records, one per version increase. When they run out, the counter stays at its last value
and newer versions still boot; refilling would need the OBK alternate-sector swap, which isn't
implemented.

The counter only ever goes up. Once a board has run version N, images below N are refused, and
only a regression resets the counter. `FW_VERSION` in CMake sets the version of the app build; it
defaults to 2 because the development board has already run version 2.

### Signing keys

- **Development key:** `tools/keys/dev_signing_key.pem`. CMake generates it on first configure
  if it doesn't exist. It's gitignored, so each developer's boards trust their own key.
- **Production key:** pass it with `-DSIGN_KEY=/path/key.pem`. Keep it offline. Both the
  bootloader (public key, generated into `btl_pubkey.h`) and the signed app (`sign.py sign`)
  are built from it, so build both with the same key.

Anyone with the signing key can install firmware that reads the device key, so it protects every
credential on every device.

`tools/sign.py` does the key work: `keygen`, `pubkey` (C header for the bootloader) and `sign`
(writes `*-signed.bin` for DFU and `*-signed.hex` for SWD; the app build runs it automatically).

## Provisioning and closing a device

A device leaves production in PRODUCT_STATE **Closed**. In Open, a debugger can read the device
key, so Closed is required. Before closing, the device gets a debug authentication (DA) password.
The password is the only way to bring a Closed device back to Open later, by a full regression
that erases everything (see [Regression](#regression)).

> **Not tested yet.** These steps follow RM0481 Rev 5 and ST's DA example
> (`STM32Cube_FW_H5_V1.6.0/Projects/NUCLEO-H533RE/ROT_Provisioning/DA`), adapted to the STM32H523
> and this firmware. Nobody has run them on a board in this project yet. Run them on a spare
> board first, and check in particular:
> - that the bootloader still starts at HDPL1 in the Provisioning and Closed states. If it
>   doesn't, the app's `obk_load_key()` fails and the device stops in `Error_Handler()` (LED on),
>   and only a regression recovers it;
> - that the regression in the last section works with the password file generated in step 1;
> - that the write protection and `NSBOOT_LOCK` from step 4 are accepted and that updates over
>   USB still work on a Closed device.

### Requirements

- STM32CubeProgrammer 2.19 or newer: `STM32_Programmer_CLI` and
  `STM32TrustedPackageCreator_CLI`, both in `STM32CubeProgrammer/bin`.
- The device in PRODUCT_STATE Open (`0xED`) with TrustZone disabled (`TZEN = 0xC3`). The WeAct
  board ships like this. Check with:

  ```sh
  STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -ob displ | grep -E "PRODUCT_STATE|TZEN"
  ```

  Never enable TrustZone on these devices. With TZEN set, DA switches from passwords to
  certificates, and the firmware's HDPL and OBK assumptions no longer hold.

### 1. Generate the DA password file (once per password)

Write `DA_ConfigWithPassword.xml`, based on ST's template:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="SCHVerif.xsd">
<Obdata>
	<Info>
		<Title>DA Config</Title>
		<ObDestAddress>0x0ffd0100</ObDestAddress>
		<DoEncryption>0</DoEncryption>
		<GlobalAlign>16</GlobalAlign>
		<MCU>STM32H533/523</MCU>
	</Info>
	<Hash>
	</Hash>
	<DA>
	</DA>
	<Text>
		<Name>Password</Name>
		<Value>CHANGE-ME-16char</Value>
		<MinWidth>4</MinWidth>
		<Width>16</Width>
		<Default>0000</Default>
		<Tooltip>Enter password</Tooltip>
	</Text>
	<Data>
		<Name>Reserved</Name>
		<Value>0x00000000</Value>
		<Width>4</Width>
		<Reserved>1</Reserved>
		<Default>0x00000000</Default>
	</Data>
	<Output>
		<Name>Output File</Name>
		<Value>DA_ConfigWithPassword.obk</Value>
		<Default>DA_ConfigWithPassword.obk</Default>
		<Tooltip>Enter Output OBKey File with extension .obk</Tooltip>
	</Output>
</Obdata>
</Root>
```

- **`DoEncryption` must be `0` on the STM32H523.** ST's template has `1`, which is meant for the
  H533. RM0481 §66.2.7 says RSS_Lib encryption must be reset on the STM32H523/543/56x.
- **`ObDestAddress` is fixed** at the start of OBK HDPL1. The bootloader's rollback records
  start 256 bytes later (0x0BFD0200), and the device key is in the HDPL2 area, so they don't
  collide.
- **Password:** up to 16 characters.

Generate the files:

```sh
STM32TrustedPackageCreator_CLI -obk DA_ConfigWithPassword.xml
```

This writes `DA_ConfigWithPassword.obk`, which holds the password hash for the device. You also
need `password.bin`, the file the programmer sends during a regression. In ST's example it sits
next to the `.obk` (`DA/Binary/password.bin`), and its format is the bytes
`00 00 00 80 10 00 00 00` followed by the 16 password characters. Check that it was produced with
the same password, then store it offline. Without it, a Closed device can't be regressed.

The password allows only a full regression, which erases the device key and all credentials
before debug opens again. Anyone who has it can wipe and repurpose a device, but can't read its
secrets. One password per production batch is therefore acceptable.

### 2. Flash the firmware

Build both targets with the production signing key (`-DSIGN_KEY=...`), then flash the bootloader
and the signed app:

```sh
STM32_Programmer_CLI -c port=SWD sn=$SN mode=UR -e all \
    -w build/btl/stm32h523-fido2-btl.hex -v -w build/app/stm32h523-fido2-signed.hex -v -rst
```

On first boot the app generates the device key and, as `-e all` left the data area blank, a new
state.

### 3. Provision DA

```sh
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -ob PRODUCT_STATE=0x17   # Provisioning
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -hardRst
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -sdp DA_ConfigWithPassword.obk
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -hardRst
```

This is the same sequence as ST's `obk_provisioning.sh`. RM0481 doesn't say whether
`-sdp` (RSSLIB_DataProvisioning) keeps the rest of the OBK areas. If this step erased the key
generated in step 2, the firmware generates a new one on the next boot; the state written with
the old key no longer decrypts, so the app erases the record area and starts with a new state.
No credentials exist yet at this point.

### 4. Protect the bootloader and close the device

```sh
# write-protect sector group 0 (4 x 8 KB = the 32 KB bootloader), lock the boot address
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -ob WRPSGn1=0xFE NSBOOT_LOCK=0xB4
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -ob PRODUCT_STATE=0x72   # Closed
```

- **WRP:** a cleared `WRPSGn1` bit protects a group of four 8 KB sectors (RM0481 §7.6.8). In
  Closed, the write protection can't be changed any more (Table 57), so neither the app nor anyone
  else can rewrite the bootloader.
- **`NSBOOT_LOCK`:** keeps the boot address at `NSBOOTADD = 0x08000000` (the default) and, with
  TrustZone disabled, also blocks `SWAP_BANK`, which could otherwise make the device boot from
  bank 2 and skip the bootloader (RM0481 §7.4, Table 57).
- Check both with `-ob displ` before closing. The option byte names are the ones
  STM32CubeProgrammer 2.19 uses for the H5; this step hasn't been tried on a board.

Debug closes immediately, so the programmer loses the connection and may report an error. That's
expected; ST's `provisioning.sh` doesn't check the return value of this command either.

Don't use **Locked** (`0x5C`) instead. It can't be regressed, even with the password, so a
device with a firmware problem can never be recovered.

### 5. Check the device

1. Power-cycle the device. It boots with the final key; the LED blinks slowly.
2. Check that it enumerates as `cafe:8008` (`lsusb`) and answers getInfo, e.g. with
   `fido2-token -I` from libfido2 or a short `python-fido2` script. `tools/fido_test.py` can't
   be used here, because it needs debug access.
3. Check that debug is closed: `STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG` must fail
   to connect. The device state can also be read through DA discovery:
   `STM32_Programmer_CLI -c port=SWD sn=$SN debugauth=2`.

A Closed device is updated over USB through the bootloader
([Updating over USB](#updating-over-usb)), signed with the production key. Updates keep the key
and the credentials.

### Regression

A full regression brings a Closed device back to Open:

```sh
STM32_Programmer_CLI -c port=SWD sn=$SN pwd=password.bin debugauth=1
```

According to RM0481 Rev 5, it:

- removes "all user flash code and data including in secure storage (HDPL1 to HDPL3)"
  (§3.11.2, product state table). Secure storage means the OBK areas (§3.1: "nonvolatile areas
  dedicated to secure storage, protected with HDPL");
- mass-erases the flash, revokes the key slots, increments the EPOCH counter and erases SRAM
  (§7.6.11, Table 43).

The device key, the DA password, the firmware and the data area (credentials, PIN) are therefore
gone. To reuse the device, start again at step 1.

## Development notes

### Building and flashing

The app only runs behind the bootloader: it is linked at 0x08008400 and needs a valid signed
header and HDPL2. On a new board, flash both once over SWD:

```sh
STM32_Programmer_CLI -c port=SWD sn=$SN mode=UR \
    -w build/btl/stm32h523-fido2-btl.hex -v -w build/app/stm32h523-fido2-signed.hex -v -rst
```

After that, the VS Code "Deploy" task flashes the active configuration over SWD (`app`: the
signed slot image, `btl`: the bootloader), and the debugger loads the same files with the `.elf`
for symbols. Updates over USB work as in [Updating over USB](#updating-over-usb).

### Checking the key on a board in OPEN state

These reads use STM32CubeProgrammer. The commit word is safe to print; the key bytes are at
`0x0BFD0900` + 48 × slot.

```sh
SN=<st-link serial>

# HDPL while the app runs: 0x6F = HDPL3 (bootloader -> 2, app after loading the key -> 3)
# reads 0 unless the SBS clock is enabled, which the firmware does
STM32_Programmer_CLI -c port=SWD sn=$SN mode=HOTPLUG -r32 0x44000414 4

# bootloader rollback records (HDPL1), readable under reset: "RBV1" 31564252, version, ~version
STM32_Programmer_CLI -c port=SWD sn=$SN mode=UR -r32 0x0BFD0200 0x80
```

The key area belongs to HDPL2, so a read under reset (HDPL1) returns zeros. To check the slot 0
commit word (`44564B31 BBA9B4CE` = provisioned, all `FF` = blank), halt the app at `main` in the
debugger, before `obk_load_key()` raises the HDPL to 3, and read 8 bytes at `0x0BFD0920`.

Avoid core-register reads (`-coreReg`) while the ROM bootloader is running (BOOT0 on an Open
board): they halt the core and the DFU interface stops responding.

### Tests

`tools/fido_test.py` runs the end-to-end CTAP2/U2F test. It simulates the buttons by
incrementing `press_count` (OK) and `next_count` (Next) through OpenOCD's TCL port, so OpenOCD
must be running and both addresses must be passed in:

```sh
openocd -f interface/stlink-dap.cfg -c "adapter serial $SN" -c "gdb_port disabled" \
        -f target/stm32h5x.cfg -c init &
ELF=build/app/stm32h523-fido2.elf
python3 tools/fido_test.py 0x$(arm-none-eabi-nm $ELF | awk '/ press_count$/{print $1}') \
                           0x$(arm-none-eabi-nm $ELF | awk '/ next_count$/{print $1}')
```

The test needs `python-fido2` (`pip install fido2`). It ends with `authenticatorReset`, which
leaves the device without credentials and without a PIN.
