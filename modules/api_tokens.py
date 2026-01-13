import json

from scripts.extract_api_tokens import get_api_tokens


def _token_name(token):
    return token.get("name") or token.get("label") or token.get("id")


def _network_signature(token):
    network = token.get("network") or {}
    return json.dumps(network, sort_keys=True, default=str)


def compare_api_tokens(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare API tokens between Env A and Env B by name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    tokensA = get_api_tokens(baseA, envA_token, limit=limit) or []
    tokensB = get_api_tokens(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_token_name(t): t for t in tokensA}
    dictB = {_token_name(t): t for t in tokensB}

    for name in dictA:
        if name not in dictB:
            diffs.append({
                "Category": "API Tokens",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "API Access",
                "Recommended Action": f"Create API token '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
        else:
            tokenA = dictA[name]
            tokenB = dictB[name]
            matches.append({
                "Category": "API Tokens",
                "Object": name,
                "Attribute": "Name",
                "Value": name
            })
            if _network_signature(tokenA) != _network_signature(tokenB):
                diffs.append({
                    "Category": "API Tokens",
                    "Object": name,
                    "Attribute": "Network",
                    "Env A Value": tokenA.get("network", ""),
                    "Env B Value": tokenB.get("network", ""),
                    "Difference Type": "Mismatch",
                    "Impact": "API Access",
                    "Recommended Action": f"Align network settings for API token '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "API Tokens",
                    "Object": name,
                    "Attribute": "Network",
                    "Value": tokenA.get("network", "")
                })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "API Tokens",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Token",
                "Recommended Action": f"Review extra API token '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
