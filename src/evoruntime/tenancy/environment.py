"""The tenant environment plane (Phase 3, G6).

A tenant is either a **research** or a **production** environment, and the
environment is policy data, not an adjective: scaffold-mutation campaigns
may run only inside a research tenant, and every boundary that could let
scaffold-class artifacts reach a production tenant checks it.

The environment lives on the tenant's signed policy document
(:mod:`evoruntime.tenancy.policy`), not on a tenants table — see that
module's docstring for why. This module holds only the vocabulary and the
scaffold-class registry both the spec validator and the registry consult.
"""

from __future__ import annotations

from enum import StrEnum

SCAFFOLD_ARTIFACT_TYPES: frozenset[str] = frozenset({"scaffold"})
"""Artifact classes that belong to the scaffold-mutation research plane.

Keyed by the artifact-type *value string* rather than the
:class:`~evoruntime.plugins.manifest.PluginArtifactType` member so the
environment plane does not depend on the scaffold class's enum landing
(G1 ships the class and its capture machinery; the value ``scaffold`` is
the class name the Phase 3 spec pins). Matching by value keeps this
registry correct the moment G1's member exists, with no edit here.
"""


class TenantEnvironment(StrEnum):
    """Which plane a tenant operates in."""

    RESEARCH = "research"
    PRODUCTION = "production"


def is_scaffold_class(artifact_type: str) -> bool:
    """True when `artifact_type` belongs to the scaffold-mutation plane."""
    return artifact_type in SCAFFOLD_ARTIFACT_TYPES


__all__ = ["SCAFFOLD_ARTIFACT_TYPES", "TenantEnvironment", "is_scaffold_class"]
