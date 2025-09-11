#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import lru_cache

__version__ = "0.1.3"
__author__ = "JackyHuang"
_PACKAGE_NAME = "uproxier"

try:
    from importlib import metadata as _ilmd
except Exception:
    _ilmd = None


@lru_cache(maxsize=1)
def get_version() -> str:
    try:
        if _ilmd is not None:
            try:
                return _ilmd.version(_PACKAGE_NAME)
            except Exception:
                return __version__
        return __version__
    except Exception:
        return __version__


def get_author() -> str:
    return __author__
