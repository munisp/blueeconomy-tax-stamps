"""RFC 6962-style Merkle tree over batch serials (batch anchoring).

Leaf hash:  SHA-256(0x00 || leaf-bytes)
Inner node: SHA-256(0x01 || left || right)

The 0x00/0x01 domain separation prevents second-preimage attacks where an
inner node is presented as a leaf. An empty tree hashes to SHA-256 of the
empty string (RFC 6962 §2.1).
"""

from __future__ import annotations

import hashlib

__all__ = ["merkle_root", "leaf_hash"]


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> str:
    """Hex Merkle root. ``leaves`` order is significant (canonical order is
    the batch's serial order)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [leaf_hash(leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            # RFC 6962 splits at the largest power of two < n; for the
            # balanced reduction used for anchoring we duplicate the last
            # node, which is deterministic and unambiguous for a fixed leaf
            # count committed alongside the root.
            level.append(level[-1])
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()
