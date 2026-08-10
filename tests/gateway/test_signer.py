# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The signing capability is a provider contract, not a raw key (ONCHAIN-S009).

The co-signer signs through a ``SignerProvider``: an address and a hash-signer,
and nothing that yields the key. Core ships ``LocalSigner`` (the reference, using
the optional ``eth_account``); a KMS/HSM provider implements the same contract in
the enterprise plane, which is why a provider that uses no ``eth_account`` at all
must satisfy it.
"""

from eth_account import Account

from secondsign.gateway.signer import LocalSigner, SignerProvider

_KEY = b"\xa1" * 32
# A representative 32-byte hash to sign (the Safe-golden value; any hash works).
_HASH = bytes.fromhex("bbdf078a1eee6cb2e877f7725ceeb6d0e83094367b6346787fe6fc273f662068")


def test_local_signer_satisfies_the_provider_contract():
    signer = LocalSigner(_KEY)
    assert isinstance(signer, SignerProvider)
    assert signer.address.startswith("0x")


def test_local_signer_produces_a_signature_that_recovers_to_its_address():
    signer = LocalSigner(_KEY)
    signature = signer.sign_hash(_HASH)
    assert signature.startswith("0x")
    recovered = Account._recover_hash(_HASH, signature=bytes.fromhex(signature.removeprefix("0x")))
    assert recovered == signer.address


def test_the_contract_exposes_no_way_to_get_the_key():
    signer = LocalSigner(_KEY)
    # The protocol surface is exactly address + sign_hash; nothing yields the key.
    public = {name for name in dir(signer) if not name.startswith("_")}
    assert public == {"address", "sign_hash"}
    for leak in ("key", "private_key", "export", "secret"):
        assert not hasattr(signer, leak)


def test_a_provider_without_eth_account_can_satisfy_the_contract():
    # The KMS boundary: a signer that never touches eth_account is a valid provider,
    # so the production implementation can live outside core.
    class FakeKmsSigner:
        def __init__(self, address: str, signature: str) -> None:
            self._address = address
            self._signature = signature

        @property
        def address(self) -> str:
            return self._address

        def sign_hash(self, tx_hash: bytes) -> str:
            return self._signature

    fake = FakeKmsSigner("0x" + "ab" * 20, "0x" + "cd" * 65)
    assert isinstance(fake, SignerProvider)
    assert fake.sign_hash(_HASH) == "0x" + "cd" * 65
    assert fake.address == "0x" + "ab" * 20
