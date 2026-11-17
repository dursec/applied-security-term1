#!/usr/bin/env python3
"""Timing attack lab: a REST API with an early-abort byte-wise compare.

Endpoints (all return JSON):
  GET  /version                                 version string, no authentication
  GET  /get_challenge?name=<name>               new 16-byte random challenge (hex) for <name>
  GET  /get_flag?name=<name>&response=<32 hex>  flag if response == AES128-ECB(key, challenge of <name>)
  POST /get_flag  {"name": "<name>", "response": "<32 hex>"}

Every name has its own challenge, so students don't interfere with each
other. get_flag always reports a simulated "runtime" for comparing the
response with the expected value, optionally with Gaussian noise added.

Requires the "cryptography" package (pip install cryptography).
"""

import argparse
import json
import os
import random
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class TimingLab:
    VERSION = "timing-attack-compare 1.1"

    # Default key and flag for local testing only. The hosted version is
    # started with a different key and flag via --key and --flag.
    KEY = bytes.fromhex("5f1c8e2ab7d04963c1e8f27a9b3d6045")
    FLAG = "flag{3arly_ab0rt_c0mpar3s_l3ak}"

    # Simulated runtime of the compare: a fixed overhead plus a cost for
    # every byte compared before the first mismatch.
    BASE_RUNTIME = 100.0
    BYTE_RUNTIME = 10.0

    # Standard deviation of the Gaussian noise added to the runtime.
    # 0 gives exact, noise-free timings.
    NOISE_STDDEV = 0.0

    # Names are student IDs or pseudonyms. When there are more than
    # MAX_NAMES, the name that asked for a challenge longest ago is dropped.
    NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
    MAX_NAMES = 10000

    HOST = "127.0.0.1"
    PORT = 8000


# Current challenge for each name, replaced on every call to /get_challenge.
# Dicts keep insertion order, so the first entry is always the oldest.
challenges = {}


def new_challenge(name):
    challenges.pop(name, None)
    challenges[name] = os.urandom(16)
    if len(challenges) > TimingLab.MAX_NAMES:
        del challenges[next(iter(challenges))]
    return challenges[name]


def expected_response(challenge):
    encryptor = Cipher(algorithms.AES(TimingLab.KEY), modes.ECB()).encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


def early_abort_compare(a, b):
    """Compare byte by byte and stop at the first mismatch.

    Returns (equal, runtime), where runtime grows with the number of bytes
    compared. This is the leak the lab is about.
    """
    runtime = TimingLab.BASE_RUNTIME
    equal = len(a) == len(b)
    for x, y in zip(a, b):
        runtime += TimingLab.BYTE_RUNTIME
        if x != y:
            equal = False
            break
    if TimingLab.NOISE_STDDEV > 0:
        runtime += random.gauss(0, TimingLab.NOISE_STDDEV)
    return equal, round(runtime, 3)


class Handler(BaseHTTPRequestHandler):
    # Keep connections open between requests; the attack needs many queries.
    protocol_version = "HTTP/1.1"
    # Send small responses at once instead of waiting for a delayed ACK.
    disable_nagle_algorithm = True

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        name = query.get("name", [None])[0]
        if url.path == "/version":
            self.send_json(200, {"version": TimingLab.VERSION})
        elif url.path == "/get_challenge":
            self.get_challenge(name)
        elif url.path == "/get_flag":
            self.get_flag(name, query.get("response", [None])[0])
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/get_flag":
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
        self.get_flag(body.get("name"), body.get("response"))

    def check_name(self, name):
        if isinstance(name, str) and TimingLab.NAME_PATTERN.fullmatch(name):
            return True
        self.send_json(400, {"error": "name must be 1 to 64 letters, digits, '-' or '_' "
                                      "(use your student ID or a random pseudonym)"})
        return False

    def get_challenge(self, name):
        if self.check_name(name):
            self.send_json(200, {"name": name, "challenge": new_challenge(name).hex()})

    def get_flag(self, name, response_hex):
        if not self.check_name(name):
            return
        if name not in challenges:
            self.send_json(400, {"error": "no challenge for this name, call get_challenge first"})
            return
        try:
            response = bytes.fromhex(response_hex or "")
        except (TypeError, ValueError):
            response = b""
        if len(response) != 16:
            self.send_json(400, {"error": "response must be 16 bytes as 32 hex characters"})
            return

        equal, runtime = early_abort_compare(response, expected_response(challenges[name]))
        if equal:
            self.send_json(200, {"flag": TimingLab.FLAG, "runtime": runtime})
        else:
            self.send_json(401, {"error": "unauthenticated", "runtime": runtime})

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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=TimingLab.HOST)
    parser.add_argument("--port", type=int, default=TimingLab.PORT)
    parser.add_argument("--noise", type=float, default=TimingLab.NOISE_STDDEV,
                        help="standard deviation of the Gaussian noise on the runtime")
    parser.add_argument("--key", help="AES-128 key as 32 hex characters (default: built-in test key)")
    parser.add_argument("--flag", help="flag to return on success (default: built-in test flag)")
    args = parser.parse_args()
    TimingLab.NOISE_STDDEV = args.noise

    if args.key is not None:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            key = b""
        if len(key) != 16:
            parser.error("--key must be 16 bytes as 32 hex characters")
        TimingLab.KEY = key
    if args.flag is not None:
        TimingLab.FLAG = args.flag

    defaults = [name for name, value in (("--key", args.key), ("--flag", args.flag)) if value is None]
    if defaults:
        print("#" * 72)
        print("#" + " WARNING: USING THE BUILT-IN TEST VALUES ".center(70, "!") + "#")
        print("#" + "".center(70) + "#")
        print("#" + f"No {' or '.join(defaults)} given, so the defaults from server.py are used.".center(70) + "#")
        print("#" + "These are public. Never use them for the hosted exercise.".center(70) + "#")
        print("#" * 72)

    server = HTTPServer((args.host, args.port), Handler)
    print(f"{TimingLab.VERSION} listening on http://{args.host}:{args.port} "
          f"(noise stddev {TimingLab.NOISE_STDDEV})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
