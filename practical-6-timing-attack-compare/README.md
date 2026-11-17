# Timing attack exercise

## The case

A small web service hands out its flag only to clients that can prove they know a secret key. The protocol is a simple challenge-response: the server sends a random 16-byte challenge, and the client has to send back the challenge encrypted with AES-128 under the shared key. You don't know the key.

The developers left a debugging aid in the service: every answer from `get_flag` includes the time the server spent checking your response. The check compares your response with the expected one byte by byte and stops at the first byte that differs.

## The service

**The URLs of the services you have to attack are on Ultra.** There are two copies of the service, which differ only in the port number:

- the one on **port 8321** reports exact runtimes, without noise (task 2)
- the one on **port 8322** adds random noise to every runtime (task 3)

Each copy has its own secret key and flag.

The full source code of the service is in [server.py](server.py). You are welcome to read it: it shows exactly how the comparison and the `runtime` work. The key and flag in `server.py` are only test values, and the services on Ultra use different ones. Finding the flag in `server.py` therefore gets you nothing, and the only way to the real flag is the timing attack.

Many students use the same services at once, so the service keeps a separate challenge for every name. **Use your student ID or a random pseudonym as `<NAME>`** and send the same name with every request. A name can be 1 to 64 letters, digits, `-` or `_`. If you share a name with someone else, you will keep resetting each other's challenge.

The service has three endpoints, all returning JSON. Replace `<URL>` with one of the addresses from Ultra, including the port:

| Endpoint | Description |
| --- | --- |
| `GET <URL>/version` | Returns the version string. No authentication. |
| `GET <URL>/get_challenge?name=<NAME>` | Returns a new 16-byte random challenge for `<NAME>` as hex. Every call replaces the previous challenge for that name. |
| `GET <URL>/get_flag?name=<NAME>&response=<32 hex characters>` | Returns the flag if `response` equals AES128-ECB(key, challenge for `<NAME>`), and the error `unauthenticated` otherwise. Every answer includes a `runtime` value for the comparison. You can also `POST` a JSON body `{"name": "<NAME>", "response": "<32 hex characters>"}`. |

For example:

```sh
curl "<URL>/get_challenge?name=<NAME>"
curl "<URL>/get_flag?name=<NAME>&response=00112233445566778899aabbccddeeff"
```

The `runtime` is simulated, so you don't have to fight real network jitter. On port 8322, random noise is added to it on purpose.

## Your task

Get the flags from the services on Ultra by recovering valid responses from the `runtime` values alone.

1. Explain why the comparison leaks information, and what the `runtime` tells you about your response.
2. Write a script that recovers a valid response byte by byte, and use it to get the flag from the copy **without noise (port 8321)**.
3. Extend your script so that it also works when the `runtime` is noisy, and get the flag from the copy **with noise (port 8322)**. How does the number of queries grow with the noise?
4. How would you fix the server so that this attack no longer works?

## Hints

- Call `get_challenge` once at the start and then leave it alone. Every call replaces the challenge for your name, and with it the response you are trying to recover.
- Think about what happens to the runtime for the very last byte.
- With noise, a single measurement per guess is not enough. Think about how many measurements you need before you can trust a difference, and whether you need to keep measuring every candidate.
- The attack takes thousands of requests. Reuse one HTTP connection (for example `requests.Session()` in Python) to keep it fast.
- Develop and debug your script against a local copy of the server first (see below), and only run it against the services on Ultra once it works.

## Running the server locally (for debugging only)

You can run `server.py` on your own machine to test your attack without waiting for the shared services. A local copy uses the test key and flag, so it is only useful for debugging: the flag and key are different from the one on the server.

The server needs Python 3 and the `cryptography` package:

```sh
pip install cryptography
python3 server.py
```

It prints a large warning that it is using the built-in test key and flag. That is expected for a local copy. It then listens on `http://127.0.0.1:8000`, so use that as `<URL>` while testing.

To practise with noise, add `--noise` with the standard deviation of the Gaussian noise to add to the `runtime` (the default is 0, no noise):

```sh
python3 server.py --noise 5
```

Try a few levels, for example 0, 5 and 10, to make sure your script copes with the noise on port 8322. `python3 server.py --help` lists the other options.
