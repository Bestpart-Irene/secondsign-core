# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Maker and checker identities — distinct types, not two values of one set.

Separation of duties (B6) is held at the type level: a :class:`MakerIdentity`
cannot be passed where a :class:`CheckerIdentity` is expected, so "the maker
approved their own request" is not an expressible mistake. The subjects are also
compared at consume time, so the same *person* cannot hold both roles even if a
deployment issues them both kinds of identity.
"""

from pydantic import BaseModel, ConfigDict, Field


class MakerIdentity(BaseModel):
    """Who requested an action be reviewed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1)


class CheckerIdentity(BaseModel):
    """Who may approve a requested action — never the same type as the maker."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1)
