"""Invoke tasks for crimson-forge."""

from invoke import Collection

from . import container

namespace = Collection(container)
