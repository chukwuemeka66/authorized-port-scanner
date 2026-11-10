import base64
import json
import random
import string
import urllib.error
import urllib.request

URL = "http://127.0.0.1:5000/receive-log"


def generate_random_string(length):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def run_fuzz_tests():
    print("[*] Starting fuzzing tests against local log receiver...")

    test_cases = [
        {
            "ciphertext": generate_random_string(32),
            "nonce": generate_random_string(12),
        },
        {
            "ciphertext": base64.b64encode(b"invalid-encrypted-data").decode("utf-8"),
            "nonce": base64.b64encode(b"shortnonce").decode("utf-8"),
        },
        {"ciphertext": ""},
    ]

    failures = 0
    for index, payload in enumerate(test_cases, 1):
        try:
            request = urllib.request.Request(
                URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                response = urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as exc:
                response = exc

            status_code = response.status
            response_body = response.read().decode("utf-8", errors="replace")
            print(f"[Test {index}] Status Code: {status_code} | Response: {response_body}")
            if status_code != 400:
                failures += 1
                print(f"[Test {index}] Expected HTTP 400 rejection.")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            failures += 1
            print(f"[Test {index}] Request failed: {exc}")

    if failures:
        raise SystemExit(f"{failures} fuzz test(s) failed.")
    print("[+] All malformed payloads were rejected.")


if __name__ == "__main__":
    run_fuzz_tests()
