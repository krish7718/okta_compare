import json

from scripts.extract_agents import get_agent_pools_with_settings

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _agent_pool_key(pool):
    return pool.get("name") or pool.get("id")


def compare_agents(envA_domain, envA_token, envB_domain, envB_token, limit_per_pool_type=200):
    """
    Compare agent pools between Env A and Env B by pool name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    poolsA = get_agent_pools_with_settings(baseA, envA_token, limit_per_pool_type=limit_per_pool_type) or []
    poolsB = get_agent_pools_with_settings(baseB, envB_token, limit_per_pool_type=limit_per_pool_type) or []

    diffs = []
    matches = []

    dictA = {_agent_pool_key(pool): pool for pool in poolsA}
    dictB = {_agent_pool_key(pool): pool for pool in poolsB}

    for name, poolA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Agents",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Agent Pool Coverage",
                "Recommended Action": f"Create agent pool '{name}' in Env B",
                "Priority": "🔴 Critical",
            })
            continue

        poolB = dictB[name]
        if _signature(poolA) != _signature(poolB):
            diffs.append({
                "Category": "Agents",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Agent Pool Drift",
                "Recommended Action": f"Align agent pool settings for '{name}'",
                "Priority": "🟠 Medium",
            })
        else:
            matches.append({
                "Category": "Agents",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match",
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Agents",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Agent Pool",
                "Recommended Action": f"Review extra agent pool '{name}' in Env B",
                "Priority": "🟡 Low",
            })

    return diffs, matches
