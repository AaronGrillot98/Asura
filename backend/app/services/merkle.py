"""Merkle tree + inclusion proofs over report evidence.

Each evidence record's `content_hash` becomes a leaf. We build a binary
SHA-256 Merkle tree, sign the root, and hand back a per-leaf inclusion
proof so a verifier can later recompute the root from a single leaf plus
O(log n) sibling hashes — without trusting the report producer for
anything other than the signed root.

Conventions match RFC 6962 (Certificate Transparency) closely:
- Leaf hashes are prefixed with `0x00`.
- Inner hashes are prefixed with `0x01`.
- Odd-length levels duplicate the last element.

Why those prefixes: they make leaf→inner collisions impossible. A signed
root commits to "this exact set of leaves," not to a generic byte
sequence that could be re-interpreted.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence


_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _hash_leaf(leaf: bytes) -> bytes:
    return _sha256(_LEAF_PREFIX + leaf)


def _hash_node(left: bytes, right: bytes) -> bytes:
    return _sha256(_NODE_PREFIX + left + right)


@dataclass(frozen=True)
class MerkleStep:
    """One step in a Merkle inclusion proof.

    `sibling` is the hex-encoded hash of the sibling node at that level.
    `side` is "left" if the sibling is to the left of the running value
    (so the verifier must hash `sibling || running`), "right" otherwise.
    """
    sibling: str
    side: str  # "left" | "right"


@dataclass(frozen=True)
class MerkleTree:
    """Materialised tree carrying the root + every level for proof
    construction. Built once per report; small enough to keep in memory."""
    leaves: list[bytes]         # hashed leaves (with `0x00` prefix)
    levels: list[list[bytes]]   # levels[0] == leaves; levels[-1] == [root]

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def inclusion_proof(self, leaf_index: int) -> list[MerkleStep]:
        """Return the audit path for the leaf at `leaf_index`."""
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"leaf_index {leaf_index} out of range (n={len(self.leaves)})")
        steps: list[MerkleStep] = []
        idx = leaf_index
        for level in self.levels[:-1]:        # everything except the root
            if idx % 2 == 0:
                # Our node is on the left; sibling is to the right.
                # Odd-length levels duplicate the last element — sibling == self.
                sibling = level[idx + 1] if idx + 1 < len(level) else level[idx]
                steps.append(MerkleStep(sibling=sibling.hex(), side="right"))
            else:
                # Our node is on the right; sibling is to the left.
                sibling = level[idx - 1]
                steps.append(MerkleStep(sibling=sibling.hex(), side="left"))
            idx //= 2
        return steps


def build_tree(leaves: Sequence[bytes | str]) -> MerkleTree:
    """Build a Merkle tree from a sequence of leaf payloads.

    Leaves are accepted as either raw bytes or hex strings (which is how
    Asura's `content_hash` already arrives). Empty input is treated as a
    tree with a single zero-leaf so the root is still defined — this
    matches RFC 6962's empty-tree convention.
    """
    if not leaves:
        # RFC 6962 empty tree: SHA-256 of the empty string. We return a
        # single-level tree with that as the root so consumers don't have
        # to special-case the empty path.
        empty_root = _sha256(b"")
        return MerkleTree(leaves=[], levels=[[empty_root]])

    hashed: list[bytes] = []
    for leaf in leaves:
        raw = bytes.fromhex(leaf) if isinstance(leaf, str) else leaf
        hashed.append(_hash_leaf(raw))

    levels: list[list[bytes]] = [hashed]
    current = hashed
    while len(current) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_hash_node(left, right))
        levels.append(next_level)
        current = next_level
    return MerkleTree(leaves=hashed, levels=levels)


def verify_inclusion(
    *,
    leaf: bytes | str,
    proof: Sequence[MerkleStep | dict],
    expected_root: bytes | str,
) -> bool:
    """Recompute the root from a leaf + audit path and compare to
    `expected_root`. Returns True on match.

    The verifier needs **only** the leaf payload, the proof, and the
    trusted root (typically obtained out-of-band from a signed report).
    No tree, no other leaves.
    """
    if isinstance(leaf, str):
        leaf = bytes.fromhex(leaf)
    if isinstance(expected_root, str):
        expected_root = bytes.fromhex(expected_root)

    running = _hash_leaf(leaf)
    for raw in proof:
        if isinstance(raw, MerkleStep):
            sibling_hex = raw.sibling
            side = raw.side
        else:
            sibling_hex = raw["sibling"]
            side = raw["side"]
        sibling = bytes.fromhex(sibling_hex)
        if side == "left":
            running = _hash_node(sibling, running)
        elif side == "right":
            running = _hash_node(running, sibling)
        else:
            return False
    return hashlib.sha256(b"").digest() == expected_root if not proof and not leaf else running == expected_root


def step_to_dict(step: MerkleStep) -> dict[str, str]:
    return {"sibling": step.sibling, "side": step.side}
