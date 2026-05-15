#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流量记录对外序列化（JSON / JSONL）的字段顺序等约定。"""

from typing import Any, Dict, Optional


def record_for_json_output(record: Dict[str, Any], *, jsonl_phase: Optional[str] = None) -> Dict[str, Any]:
    """
    生成写入 JSON/JSONL 的 dict：去掉 _ 前缀内部键；flow_id 固定放在最后
    （jsonl_phase 若有，在 flow_id 之前）。
    """
    base = {
        k: v
        for k, v in record.items()
        if not (isinstance(k, str) and k.startswith("_"))
    }
    fid = base.pop("flow_id", None)
    out: Dict[str, Any] = dict(base)
    if jsonl_phase is not None:
        out["jsonl_phase"] = jsonl_phase
    if fid is not None:
        out["flow_id"] = fid
    return out
