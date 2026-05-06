import argparse
import asyncio

from ipv8.configuration import ConfigBuilder
from ipv8_service import IPv8


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--key-file",
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

    # IPv8 configuration.
    builder = ConfigBuilder().clear_keys().clear_overlays()

    # If the key file does not exist, IPv8 will create it.
    # If it already exists, IPv8 will load the same identity again.
    builder.add_key(
        "lab-key",
        "curve25519",
        args.key_file,
    )

    ipv8 = IPv8(builder.finalize())

    await ipv8.start()

    # The private key stays in the .pem file.
    # This prints only the public key, which is safe to share.
    peer = ipv8.keys["lab-key"]
    print("IPv8 identity loaded.")
    print("Private key file:", args.key_file)
    print("Public key:", peer.public_key.key_to_bin().hex())

    await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())