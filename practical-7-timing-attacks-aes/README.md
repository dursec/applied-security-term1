# AES timing attack exercise

## The case

A small server encrypts data with AES-128 under a secret key. Its developers implemented AES straight from the specification, including this function from MixColumns, which multiplies a byte by 02 in GF(2^8):

```c
uint8_t xtime(uint8_t b)
{
    uint8_t r = b << 1;
    if (b & 0x80)
        r ^= 0x1B;
    return r;
}
```

The `if` means `xtime()` spends an extra cycle when the most significant bit of its input is set. The server lets you encrypt plaintexts of your choice, and for every encryption it also reports two measurements of how `xtime()` behaved. Your job is to recover the key from those measurements.

## The service

**The URL of the service you have to attack is on Ultra** (port 8323). It runs with its own secret key and flag.

The full source code of the service is in [server.py](server.py), including the AES implementation. You are welcome to read it. The key and flag in `server.py` are only test values, and the service on Ultra uses different ones, so the only way to the real flag is to recover the key.

The service has three endpoints, all returning JSON. Replace `<URL>` with the address from Ultra:

| Endpoint | Description |
| --- | --- |
| `GET <URL>/version` | Returns the version string. |
| `GET <URL>/encrypt?plaintext=<32 hex characters>` | Encrypts one 16-byte block and returns the ciphertext and the two leakages described below. You can also `POST` a JSON body `{"plaintext": "<32 hex characters>"}`. |
| `POST <URL>/encrypt` with `{"plaintexts": [...]}` | Encrypts up to 1000 blocks in one request and returns a list of results. Use this when you need many encryptions. |
| `GET <URL>/get_flag?key=<32 hex characters>` | Returns the flag if `key` is the AES key, and the error `wrong key` otherwise. This check is constant-time, so the trick from the comparison exercise won't work here. |

For example:

```sh
curl "<URL>/encrypt?plaintext=00112233445566778899aabbccddeeff"
```

returns, on a local copy of the server with the test key and no noise:

```json
{"plaintext": "00112233445566778899aabbccddeeff", "ciphertext": "798c2f69504e3427cc020f8c50bce5a2",
 "xtime_round1": [1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0], "runtime": 72.0}
```

The service on Ultra has a different key, so it returns different values.

### The two leakages

- **`xtime_round1`** is a list of 16 values, one for each `xtime()` call in the first round's MixColumns, in the order the calls happen. Each value is 1 if that call did the conditional XOR and 0 if it didn't. This simulates watching the program flow of a single `xtime()` in a power trace. It is always exact.
- **`runtime`** is the total number of conditional XORs over all `xtime()` calls in the whole encryption (16 per round, 9 rounds), standing in for the encryption time. The service may add random noise to it.

Both values are simulated by counting inside the AES code, not measured, so you don't have to fight real network jitter.

## Your task

1. Explain why `xtime()` leaks information about the key. Which intermediate value of the first round does it reveal, and how does that value depend on the plaintext and the key?
2. **Part 1:** using only `xtime_round1`, recover the full key and get the flag. How many encryptions did you need, and why that many?
3. **Part 2:** now pretend you can only measure `runtime`. Using only `runtime` and the plaintexts (not `xtime_round1` and not the ciphertexts), recover the full key again. How many encryptions did you need? How does that number change with the noise (test this locally)?
4. How would you implement `xtime()` so that it doesn't leak? What do you have to watch out for?

## Hints

- MixColumns runs after SubBytes and ShiftRows. Work out which byte of the state goes into which `xtime()` call: the first four calls handle the first column of the state after ShiftRows, the next four the second column, and so on. Look at `SHIFT_ROWS_TABLE` and `aes_enc()` in `server.py`.
- In the first round, the input to SubBytes is the plaintext XOR the key. You know the plaintext, so for each key byte you can try all 256 values and predict what `xtime()` should do.
- For Part 1, follow the lecture: attack one key byte at a time and keep a list of the values that are still possible. Every encryption gives you one bit for each of the 16 key bytes, so you can reuse the same encryptions for all of them.
- For Part 2, only one of the 144 `xtime()` calls depends on a given key byte in the way you can predict. The other calls look like noise. Think about how averaging over many encryptions, split by your prediction, makes the one call you predicted correctly stand out.
- Part 2 needs thousands of encryptions. Use the batch form of `/encrypt`, and reuse one HTTP connection (for example `requests.Session()` in Python).
- You can check a key guess yourself by encrypting a plaintext with it (for example with Python's `cryptography` package) and comparing with the ciphertext from the service, or simply by asking `get_flag`.

## Running the server locally (for debugging only)

You can run `server.py` on your own machine to test your attacks without using the shared service. A local copy uses the test key and flag, so it is only useful for debugging: the flag it returns is not the one you need to hand in.

The server only needs Python 3:

```sh
python3 server.py
```

It prints a large warning that it is using the built-in test key and flag. That is expected for a local copy. It then listens on `http://127.0.0.1:8000`, so use that as `<URL>` while testing.

To practise Part 2 with noise, add `--noise` with the standard deviation of the Gaussian noise to add to `runtime` (the default is 0, no noise). `xtime_round1` is never noisy.

```sh
python3 server.py --noise 10
```

Try a few levels, for example 0, 10 and 20, and see how many encryptions your attack needs. `python3 server.py --help` lists the other options.
