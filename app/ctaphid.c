#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header
#include "tusb.h"

#include "boot.h"
#include "ctap2.h"
#include "u2f.h"
#include "up.h"
#include "update.h"
#include "watchdog.h"

#include "ctaphid.h"

/* FIDO CTAP 2.1, chapter 11.2 USB Human Interface Device (USB HID) */

#define CID_BROADCAST 0xffffffffU

#define TYPE_INIT 0x80

#define CMD_PING      0x01
#define CMD_MSG       0x03
#define CMD_LOCK      0x04
#define CMD_INIT      0x06
#define CMD_WINK      0x08
#define CMD_CBOR      0x10
#define CMD_CANCEL    0x11
#define CMD_KEEPALIVE 0x3b
#define CMD_ERROR     0x3f

/* vendor commands (0x40..0x7f) */
#define CMD_BOOTLOADER 0x50 /* touch, then reset into the bootloader (signed images over USB DFU) */

#define ERR_INVALID_CMD     0x01
#define ERR_INVALID_PAR     0x02
#define ERR_INVALID_LEN     0x03
#define ERR_INVALID_SEQ     0x04
#define ERR_MSG_TIMEOUT     0x05
#define ERR_CHANNEL_BUSY    0x06
#define ERR_INVALID_CHANNEL 0x0b
#define ERR_OTHER           0x7f

#define CAPABILITY_WINK 0x01
#define CAPABILITY_CBOR 0x04

#define INIT_DATA_SIZE (CTAPHID_PACKET_SIZE - 7)
#define CONT_DATA_SIZE (CTAPHID_PACKET_SIZE - 5)

#define MSG_TIMEOUT_MS  500
#define KEEPALIVE_MS    100
#define TX_TIMEOUT_MS   1000
#define PENDING_PACKETS 4

typedef enum
{
    RX_IDLE,
    RX_ASSEMBLING,
    RX_READY,
    RX_BUSY,
} rx_state_t;

static struct
{
    rx_state_t state;
    uint32_t cid;
    uint8_t cmd;
    uint16_t len;
    uint16_t got;
    uint8_t seq;
    uint32_t tick;
} rx;

static uint8_t msg_buf[CTAPHID_MAX_MSG];
static uint8_t resp_buf[CTAPHID_MAX_MSG];

static uint32_t next_cid = 1;
static bool cancelled = false;
static uint32_t keepalive_tick = 0;

/* single packet replies generated in the USB callback (INIT, errors), sent from main context */
static uint8_t pending[PENDING_PACKETS][CTAPHID_PACKET_SIZE];
static uint8_t pending_head = 0;
static uint8_t pending_count = 0;
static bool flushing = false;

static uint32_t get_cid(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_cid(uint8_t *p, uint32_t cid)
{
    p[0] = (uint8_t)(cid >> 24);
    p[1] = (uint8_t)(cid >> 16);
    p[2] = (uint8_t)(cid >> 8);
    p[3] = (uint8_t)cid;
}

static void init_packet(uint8_t *pkt, uint32_t cid, uint8_t cmd, uint16_t len)
{
    memset(pkt, 0, CTAPHID_PACKET_SIZE);
    put_cid(pkt, cid);
    pkt[4] = TYPE_INIT | cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)len;
}

static void queue_packet(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    uint8_t *pkt;

    if (pending_count >= PENDING_PACKETS)
    {
        return;
    }
    pkt = pending[(pending_head + pending_count) % PENDING_PACKETS];
    init_packet(pkt, cid, cmd, len);
    memcpy(&pkt[7], data, len);
    pending_count++;
}

static void queue_error(uint32_t cid, uint8_t code)
{
    queue_packet(cid, CMD_ERROR, &code, 1);
}

static bool send_packet(const uint8_t *pkt)
{
    uint32_t start = HAL_GetTick();

    while (!tud_hid_n_ready(HID_ITF_FIDO))
    {
        tud_task();
        if (!tud_mounted() || (HAL_GetTick() - start) > TX_TIMEOUT_MS)
        {
            return false;
        }
    }
    return tud_hid_n_report(HID_ITF_FIDO, 0, pkt, CTAPHID_PACKET_SIZE);
}

static void send_message(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    uint8_t pkt[CTAPHID_PACKET_SIZE];
    uint16_t off;
    uint16_t n;
    uint8_t seq = 0;

    init_packet(pkt, cid, cmd, len);
    n = len < INIT_DATA_SIZE ? len : INIT_DATA_SIZE;
    memcpy(&pkt[7], data, n);
    off = n;
    if (!send_packet(pkt))
    {
        return;
    }

    while (off < len)
    {
        memset(pkt, 0, sizeof(pkt));
        put_cid(pkt, cid);
        pkt[4] = seq++;
        n = (len - off) < CONT_DATA_SIZE ? (len - off) : CONT_DATA_SIZE;
        memcpy(&pkt[5], &data[off], n);
        off += n;
        if (!send_packet(pkt))
        {
            return;
        }
    }
}

static void send_error(uint32_t cid, uint8_t code)
{
    send_message(cid, CMD_ERROR, &code, 1);
}

static void flush_pending(void)
{
    if (flushing)
    {
        return;
    }
    flushing = true;
    while (pending_count)
    {
        send_packet(pending[pending_head]);
        pending_head = (pending_head + 1) % PENDING_PACKETS;
        pending_count--;
    }
    flushing = false;
}

static bool cid_valid(uint32_t cid)
{
    return cid != 0 && cid != CID_BROADCAST && cid < next_cid;
}

static void rx_init_cmd(uint32_t cid, const uint8_t *pkt, uint16_t bcnt)
{
    uint8_t resp[17];
    uint32_t new_cid;

    if (bcnt != 8)
    {
        queue_error(cid, ERR_INVALID_LEN);
        return;
    }

    if (cid == CID_BROADCAST)
    {
        new_cid = next_cid++;
        if (next_cid == CID_BROADCAST)
        {
            next_cid = 1;
        }
    }
    else if (cid_valid(cid))
    {
        /* resynchronize the channel, abort anything pending on it */
        new_cid = cid;
        if (rx.cid == cid)
        {
            if (rx.state == RX_ASSEMBLING || rx.state == RX_READY)
            {
                rx.state = RX_IDLE;
            }
            else if (rx.state == RX_BUSY)
            {
                cancelled = true;
            }
        }
    }
    else
    {
        queue_error(cid, ERR_INVALID_CHANNEL);
        return;
    }

    memcpy(resp, &pkt[7], 8); /* nonce */
    put_cid(&resp[8], new_cid);
    resp[12] = 2; /* CTAPHID protocol version */
    resp[13] = 1; /* device version major.minor.build */
    resp[14] = 0;
    resp[15] = 0;
    resp[16] = CAPABILITY_WINK | CAPABILITY_CBOR;
    queue_packet(cid, CMD_INIT, resp, sizeof(resp));
}

void ctaphid_init(void)
{
    memset(&rx, 0, sizeof(rx));
}

void ctaphid_rx(const uint8_t *pkt, uint16_t len)
{
    uint32_t cid;
    uint16_t n;

    if (len < CTAPHID_PACKET_SIZE)
    {
        return;
    }
    cid = get_cid(pkt);

    if (pkt[4] & TYPE_INIT)
    {
        uint8_t cmd = pkt[4] & ~TYPE_INIT;
        uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];

        if (cmd == CMD_INIT)
        {
            rx_init_cmd(cid, pkt, bcnt);
            return;
        }

        if (!cid_valid(cid))
        {
            queue_error(cid, ERR_INVALID_CHANNEL);
            return;
        }

        if (cmd == CMD_CANCEL)
        {
            if (rx.cid == cid)
            {
                if (rx.state == RX_BUSY)
                {
                    cancelled = true;
                }
                else if (rx.state == RX_ASSEMBLING || rx.state == RX_READY)
                {
                    rx.state = RX_IDLE;
                }
            }
            return;
        }

        if (rx.state != RX_IDLE)
        {
            if (rx.cid == cid && rx.state == RX_ASSEMBLING)
            {
                rx.state = RX_IDLE;
                queue_error(cid, ERR_INVALID_SEQ);
            }
            else
            {
                queue_error(cid, ERR_CHANNEL_BUSY);
            }
            return;
        }

        if (bcnt > CTAPHID_MAX_MSG)
        {
            queue_error(cid, ERR_INVALID_LEN);
            return;
        }

        rx.cid = cid;
        rx.cmd = cmd;
        rx.len = bcnt;
        rx.seq = 0;
        rx.tick = HAL_GetTick();
        n = bcnt < INIT_DATA_SIZE ? bcnt : INIT_DATA_SIZE;
        memcpy(msg_buf, &pkt[7], n);
        rx.got = n;
        rx.state = (rx.got == rx.len) ? RX_READY : RX_ASSEMBLING;
    }
    else
    {
        /* continuation packets out of a transaction are ignored */
        if (rx.state != RX_ASSEMBLING || rx.cid != cid)
        {
            return;
        }
        if (pkt[4] != rx.seq)
        {
            rx.state = RX_IDLE;
            queue_error(cid, ERR_INVALID_SEQ);
            return;
        }
        rx.seq++;
        rx.tick = HAL_GetTick();
        n = (rx.len - rx.got) < CONT_DATA_SIZE ? (rx.len - rx.got) : CONT_DATA_SIZE;
        memcpy(&msg_buf[rx.got], &pkt[5], n);
        rx.got += n;
        if (rx.got == rx.len)
        {
            rx.state = RX_READY;
        }
    }
}

static void process(void)
{
    uint32_t cid = rx.cid;
    size_t n;

    switch (rx.cmd)
    {
    case CMD_PING:
        send_message(cid, CMD_PING, msg_buf, rx.len);
        break;

    case CMD_WINK:
        up_wink();
        send_message(cid, CMD_WINK, NULL, 0);
        break;

    case CMD_MSG:
        n = u2f_process(msg_buf, rx.len, resp_buf, sizeof(resp_buf));
        send_message(cid, CMD_MSG, resp_buf, (uint16_t)n);
        break;

    case CMD_CBOR:
        if (rx.len == 0)
        {
            send_error(cid, ERR_INVALID_LEN);
            break;
        }
        n = ctap2_process(msg_buf, rx.len, resp_buf, sizeof(resp_buf));
        send_message(cid, CMD_CBOR, resp_buf, (uint16_t)n);
        break;

    case CMD_BOOTLOADER:
    {
        uint32_t start;
        uint8_t status;

        up_prompt_text("Firmware update?", "Restarts into the", "bootloader");
        status = ctap2_wait_up();
        start = HAL_GetTick();

        send_message(cid, CMD_BOOTLOADER, &status, 1);
        if (status == 0)
        {
            /* let the reply leave before the reset */
            while (!tud_hid_n_ready(HID_ITF_FIDO) && (HAL_GetTick() - start) < TX_TIMEOUT_MS)
            {
                tud_task();
            }
            BOOT_REQUEST = BOOT_REQUEST_MAGIC;
            schedule_reset();
        }
        break;
    }

    default:
        send_error(cid, ERR_INVALID_CMD);
        break;
    }
}

void ctaphid_task(void)
{
    flush_pending();
    up_tick();
    u2f_tick();

    if (rx.state == RX_ASSEMBLING && (HAL_GetTick() - rx.tick) > MSG_TIMEOUT_MS)
    {
        rx.state = RX_IDLE;
        queue_error(rx.cid, ERR_MSG_TIMEOUT);
    }

    if (rx.state == RX_READY)
    {
        rx.state = RX_BUSY;
        cancelled = false;
        keepalive_tick = HAL_GetTick();
        process();
        rx.state = RX_IDLE;
        flush_pending();
    }
}

bool ctaphid_poll(uint8_t status)
{
    uint8_t pkt[CTAPHID_PACKET_SIZE];

    tud_task();
    flush_pending();
    up_tick();
    WDI();

    if (rx.state == RX_BUSY && (HAL_GetTick() - keepalive_tick) >= KEEPALIVE_MS)
    {
        keepalive_tick = HAL_GetTick();
        init_packet(pkt, rx.cid, CMD_KEEPALIVE, 1);
        pkt[7] = status;
        send_packet(pkt);
    }
    return cancelled;
}
