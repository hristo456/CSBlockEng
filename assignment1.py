import argparse
import asyncio
import hashlib
import time
from ipv8.configuration import ConfigBuilder
from ipv8_service import IPv8


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--key-file",
        required=True,
        help="Private key. Don't commit.",
    )

    parser.add_argument(
        "--email",
        required=True,
        help="Your official TU Delft email address.",
    )

    parser.add_argument(
        "--github-url",
        required=True,
        help="The public GitHub repository URL for this lab.",
    )

    args = parser.parse_args()

    if ((not args.email.endswith("@tudelft.nl")) and (not args.email.endswith("@student.tudelft.nl"))) or len(args.email.encode("utf-8")) > 254:
        print("Invalid email address. Please provide a valid TU Delft email address.")
        return
    
    if (len(args.github_url) == 0) or len(args.github_url.encode("utf-8")) > 512:
        print("Invalid GitHub repository URL. Please provide a valid URL.")
        return

    email_bytes = args.email.replace("\n", "").encode("utf-8")
    github_url_bytes = args.github_url.replace("\n", "").encode("utf-8")

    # IPv8 configuration.
    builder = ConfigBuilder().clear_keys().clear_overlays()

    # Key loader
    builder.add_key(
        "lab-key",
        "curve25519",
        args.key_file,
    )

    ipv8 = IPv8(builder.finalize())

    await ipv8.start()

    peer = ipv8.keys["lab-key"]
    print("IPv8 identity loaded.")
    print("Private key file:", args.key_file)
    print("Public key:", peer.public_key.key_to_bin().hex())

    hash_prefix = email_bytes + b"\n" + github_url_bytes + b"\n"

    print("Starting local Proof of Work search...")
    start_time = time.time()
    nonce = 0

    while True:
        nonce_bytes = nonce.to_bytes(8)

        digest = hashlib.sha256(hash_prefix + nonce_bytes).digest()

        # 28 leading zero bits means: first byte is 0, second byte is 0, third byte is 0 and top 4 bits of fourth byte are 0
        if digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16:
            elapsed = time.time() - start_time

            print()
            print("Found valid nonce!")
            print("Nonce:", nonce)
            print("Hash:", digest.hex())
            print("Elapsed seconds:", round(elapsed, 2))

            break

        nonce += 1

    await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())