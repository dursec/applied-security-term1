#!/usr/bin/env python3
"""Timing attack lab: AES-128 with a leaky xtime() in MixColumns.

Endpoints (all return JSON):
  GET  /version                              version string, no authentication
  GET  /encrypt?plaintext=<32 hex>           encrypt one block and report its leakage
  POST /encrypt  {"plaintext": "<32 hex>"}   same as GET
  POST /encrypt  {"plaintexts": [...]}       encrypt up to MAX_BATCH blocks at once
  GET  /get_flag?key=<32 hex>                flag if key is the server's AES key
  POST /get_flag  {"key": "<32 hex>"}

Every encryption reports two simulated leakages of xtime(), which only does
its conditional XOR when the most significant bit of its input is set:
  xtime_round1  the 16 conditional XORs of the first round (1 = XOR done),
                in the order xtime() is called
  runtime       the number of conditional XORs over all rounds, plus optional
                Gaussian noise

The key comparison in get_flag is constant-time.
"""

import argparse
import hmac
import json
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class AesTimingLab:
    VERSION = "timing-attacks-aes 1.0"

    # Default key and flag for local testing only. The hosted version is
    # started with a different key and flag via --key and --flag.
    KEY = bytes.fromhex("123456789abcde0f1122334455667788")
    FLAG = "flag{xt1m3_l3aks_th3_k3y}"

    # Standard deviation of the Gaussian noise added to "runtime".
    # "xtime_round1" is never noisy.
    NOISE_STDDEV = 0.0

    # Maximum number of plaintexts in one POST /encrypt.
    MAX_BATCH = 1000

    HOST = "127.0.0.1"
    PORT = 8000


# AES-128 encryption, ported from aes.cpp: same tables and structure, but
# xtime() counts its conditional XORs to simulate a timing leak.

SHIFT_ROWS_TABLE = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
RCON = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def expand_key(key):
    """Expand the 16-byte key to 11 round keys (176 bytes)."""
    keys = list(key)
    i = 1
    while len(keys) < 176:
        # Key schedule core on the previous 4 bytes: rotate, S-box, rcon
        t = keys[-4:]
        t = [SBOX[b] for b in t[1:] + t[:1]]
        t[0] ^= RCON[i]
        i += 1
        keys += [t[j] ^ keys[-16 + j] for j in range(4)]
        # The next 12 bytes are the previous 4 XOR the 4 bytes 16 earlier
        for _ in range(3):
            keys += [keys[-4 + j] ^ keys[-16 + j] for j in range(4)]
    return keys


def xtime(b, leaks):
    """Multiply by 02 in GF(2^8). The conditional XOR is the timing leak:
    it is only done when the MSB of b is set, and every time it happens a 1
    is appended to leaks (otherwise a 0)."""
    r = (b << 1) & 0xff
    if b & 0x80:
        r ^= 0x1b
        leaks.append(1)
    else:
        leaks.append(0)
    return r


def mix_col(state, i, leaks):
    a0, a1, a2, a3 = state[i:i + 4]
    a0_g2 = xtime(a0, leaks)
    a1_g2 = xtime(a1, leaks)
    a2_g2 = xtime(a2, leaks)
    a3_g2 = xtime(a3, leaks)
    a0_g3 = a0 ^ a0_g2
    a1_g3 = a1 ^ a1_g2
    a2_g3 = a2 ^ a2_g2
    a3_g3 = a3 ^ a3_g2
    state[i] = a0_g2 ^ a1_g3 ^ a2 ^ a3
    state[i + 1] = a1_g2 ^ a2_g3 ^ a3 ^ a0
    state[i + 2] = a2_g2 ^ a3_g3 ^ a0 ^ a1
    state[i + 3] = a3_g2 ^ a0_g3 ^ a1 ^ a2


def aes_enc(msg, keys):
    """Encrypt one 16-byte block with expanded key `keys`.

    Returns (ciphertext, leaks), where leaks has one 0/1 entry per xtime()
    call: 16 per round for the 9 rounds with MixColumns, 144 in total.
    """
    leaks = []
    state = [m ^ k for m, k in zip(msg, keys[0:16])]

    for rnd in range(1, 10):
        state = [SBOX[b] for b in state]
        state = [state[j] for j in SHIFT_ROWS_TABLE]
        for i in (0, 4, 8, 12):
            mix_col(state, i, leaks)
        state = [s ^ k for s, k in zip(state, keys[16 * rnd:16 * rnd + 16])]

    state = [SBOX[b] for b in state]
    state = [state[j] for j in SHIFT_ROWS_TABLE]
    state = [s ^ k for s, k in zip(state, keys[160:176])]
    return bytes(state), leaks


round_keys = expand_key(AesTimingLab.KEY)


def encrypt_with_leakage(plaintext):
    ciphertext, leaks = aes_enc(plaintext, round_keys)
    runtime = float(sum(leaks))
    if AesTimingLab.NOISE_STDDEV > 0:
        runtime += random.gauss(0, AesTimingLab.NOISE_STDDEV)
    return {
        "plaintext": plaintext.hex(),
        "ciphertext": ciphertext.hex(),
        "xtime_round1": leaks[:16],
        "runtime": round(runtime, 3),
    }


def parse_block(value):
    """16 bytes from 32 hex characters, or None."""
    try:
        block = bytes.fromhex(value)
    except (TypeError, ValueError):
        return None
    return block if len(block) == 16 else None


class Handler(BaseHTTPRequestHandler):
    # Keep connections open between requests; the attack needs many queries.
    protocol_version = "HTTP/1.1"
    # Send small responses at once instead of waiting for a delayed ACK.
    disable_nagle_algorithm = True

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/version":
            self.send_json(200, {"version": AesTimingLab.VERSION})
        elif url.path == "/encrypt":
            self.encrypt({"plaintext": query.get("plaintext", [None])[0]})
        elif url.path == "/get_flag":
            self.get_flag(query.get("key", [None])[0])
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path not in ("/encrypt", "/get_flag"):
            self.send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "invalid JSON"})
            return
        if not isinstance(body, dict):
            body = {}
        if url.path == "/encrypt":
            self.encrypt(body)
        else:
            self.get_flag(body.get("key"))

    def encrypt(self, body):
        if "plaintexts" in body:
            values = body["plaintexts"]
            if not isinstance(values, list) or not 1 <= len(values) <= AesTimingLab.MAX_BATCH:
                self.send_json(400, {"error": f"plaintexts must be a list of 1 to {AesTimingLab.MAX_BATCH} blocks"})
                return
            blocks = [parse_block(v) for v in values]
            if None in blocks:
                self.send_json(400, {"error": "every plaintext must be 16 bytes as 32 hex characters"})
                return
            self.send_json(200, {"results": [encrypt_with_leakage(b) for b in blocks]})
            return

        block = parse_block(body.get("plaintext"))
        if block is None:
            self.send_json(400, {"error": "plaintext must be 16 bytes as 32 hex characters"})
            return
        self.send_json(200, encrypt_with_leakage(block))

    def get_flag(self, key_hex):
        key = parse_block(key_hex)
        if key is None:
            self.send_json(400, {"error": "key must be 16 bytes as 32 hex characters"})
            return
        if hmac.compare_digest(key, AesTimingLab.KEY):
            self.send_json(200, {"flag": AesTimingLab.FLAG})
        else:
            self.send_json(401, {"error": "wrong key"})

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Thousands of requests are expected, so don't log each one.
        pass


def main():
    global round_keys

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=AesTimingLab.HOST)
    parser.add_argument("--port", type=int, default=AesTimingLab.PORT)
    parser.add_argument("--noise", type=float, default=AesTimingLab.NOISE_STDDEV,
                        help="standard deviation of the Gaussian noise on runtime (not on xtime_round1)")
    parser.add_argument("--key", help="AES-128 key as 32 hex characters (default: built-in test key)")
    parser.add_argument("--flag", help="flag to return on success (default: built-in test flag)")
    args = parser.parse_args()
    AesTimingLab.NOISE_STDDEV = args.noise

    if args.key is not None:
        key = parse_block(args.key)
        if key is None:
            parser.error("--key must be 16 bytes as 32 hex characters")
        AesTimingLab.KEY = key
        round_keys = expand_key(key)
    if args.flag is not None:
        AesTimingLab.FLAG = args.flag

    defaults = [name for name, value in (("--key", args.key), ("--flag", args.flag)) if value is None]
    if defaults:
        print("#" * 72)
        print("#" + " WARNING: USING THE BUILT-IN TEST VALUES ".center(70, "!") + "#")
        print("#" + "".center(70) + "#")
        print("#" + f"No {' or '.join(defaults)} given, so the defaults from server.py are used.".center(70) + "#")
        print("#" + "These are public. Never use them for the hosted exercise.".center(70) + "#")
        print("#" * 72)

    server = HTTPServer((args.host, args.port), Handler)
    print(f"{AesTimingLab.VERSION} listening on http://{args.host}:{args.port} "
          f"(noise stddev {AesTimingLab.NOISE_STDDEV})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
