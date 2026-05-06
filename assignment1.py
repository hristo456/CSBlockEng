import argparse
import asyncio
import hashlib
import time
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.community import Community
from ipv8.peer import Peer
from ipv8_service import IPv8
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile

@vp_compile
class SubmissionPayload(VariablePayload):
    msg_id = 1

    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


@vp_compile
class ResponsePayload(VariablePayload):
    msg_id = 2

    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class LabCommunity(Community):
    community_id = b""
    server_public_key = b""
    email=b""
    github_url=b""
    nonce=0

    def __init__(self, settings):
        super().__init__(settings)
        
        self.submission_sent = False
        self.add_message_handler(ResponsePayload, self.on_response)

    def started(self):
        print("Joining Lab community.")
        self.register_task(
            "find_server",
            self.find_server,
            interval=2.0,
            delay=0,
        )

    async def find_server(self):
        if self.submission_sent:
            return
        
        for peer in self.get_peers():
            peer_public_key = peer.public_key.key_to_bin()

            if peer_public_key == self.server_public_key:
                print("Verified server found:", peer.address)
                self.ez_send(
                    peer,
                    SubmissionPayload(
                        self.email,
                        self.github_url,
                        self.nonce,
                    ),
                )

                self.submission_sent = True
                return
            
    def on_peer_added(self, peer: Peer):
        peer_public_key = peer.public_key.key_to_bin()

        print("Discovered peer:", peer_public_key.hex())

        if peer_public_key == self.server_public_key:
            print()
            print("Verified server found!")
            print("Server address:", peer.address)
            print("Server public key:", peer_public_key.hex())
            print()
            return

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload):
        peer_public_key = peer.public_key.key_to_bin()

        if peer_public_key != self.server_public_key:
            print("Ignored response from non-server peer.")
            return

        print("Server response received.")
        print("Success:", payload.success)
        print("Message:", payload.message)

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
    )

    parser.add_argument(
        "--github-url",
        required=True,
    )

    parser.add_argument(
    "--community-id",
    required=True,
    )

    parser.add_argument(
    "--server-public-key",
    required=True,
    )

    args = parser.parse_args()

    if "\n" in args.email:
        print("Email must not contain a newline.")
        return

    if "\n" in args.github_url:
        print("GitHub URL must not contain a newline.")
        return

    if ((not args.email.endswith("@tudelft.nl")) and (not args.email.endswith("@student.tudelft.nl"))) or len(args.email.encode("utf-8")) > 254:
        print("Invalid email address. Please provide a valid TU Delft email address.")
        return
    
    if (len(args.github_url) == 0) or len(args.github_url.encode("utf-8")) > 512:
        print("Invalid GitHub repository URL. Please provide a valid URL.")
        return
    
    if len(args.community_id) != 40:
        raise ValueError("Community ID must be 40 hex characters.")

    if len(args.server_public_key) != 148:
        raise ValueError("Server public key must be 148 hex characters.")

    LabCommunity.community_id = bytes.fromhex(args.community_id)
    LabCommunity.server_public_key = bytes.fromhex(args.server_public_key)
    LabCommunity.email = args.email
    LabCommunity.github_url = args.github_url

    email_bytes = args.email.encode("utf-8")
    github_url_bytes = args.github_url.encode("utf-8")

    # IPv8 configuration.
    builder = ConfigBuilder().clear_keys().clear_overlays()

    # Key loader
    builder.add_key(
        "lab-key",
        "curve25519",
        args.key_file,
    )

    builder.add_overlay(
        "LabCommunity",
        "lab-key",
        [
            WalkerDefinition(
                Strategy.RandomWalk,
                20,
                {"timeout": 3.0},
            )
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "LabCommunity": LabCommunity,
        },
    )

    peer = ipv8.keys["lab-key"]
    print("IPv8 identity loaded.")
    print("Private key file:", args.key_file)
    print("Public key:", peer.public_key.key_to_bin().hex())

    hash_prefix = email_bytes + b"\n" + github_url_bytes + b"\n"

    print("Starting local Proof of Work search...")
    start_time = time.time()
    nonce = 0
    max_nonce = 2**63 - 1

    while nonce <= max_nonce:
        nonce_bytes = nonce.to_bytes(8, byteorder="big", signed=False)

        digest = hashlib.sha256(hash_prefix + nonce_bytes).digest()

        # 28 leading zero bits means: first byte is 0, second byte is 0, third byte is 0 and top 4 bits of fourth byte are 0
        if digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16:
            elapsed = time.time() - start_time

            print()
            print("Found valid nonce!")
            print("Nonce:", nonce)
            print("Hash:", digest.hex())
            print("Elapsed seconds:", round(elapsed, 2))
            LabCommunity.nonce = nonce
            break

        nonce += 1
    else:
        raise RuntimeError("No valid nonce found before reaching the int64 limit.")

    await ipv8.start()
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())