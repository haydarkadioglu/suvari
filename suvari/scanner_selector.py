"""
Tool Profiler — tool profiles, execution times, and smart selection.
Uses rules + AI hints to pick the right tools for the target.
"""

import time
from typing import Optional
from .tools.runner import ToolRunner


# Tool speed classifications (estimated max time in seconds)
TOOL_PROFILES = {
    "nmap": {
        "speed": "medium",  # -F quick scan is fast, full scan is slow
        "max_time": 120,
        "variants": {"fast": ["nmap", "-T4", "-F", "--open"], "full": ["nmap", "-T4", "-p-", "--open"]},
        "best_for": ["all"],
    },
    "whatweb": {
        "speed": "fast",
        "max_time": 30,
        "variants": {"fast": ["whatweb"], "full": ["whatweb", "-v"]},
        "best_for": ["all"],
    },
    "nuclei": {
        "speed": "fast",
        "max_time": 60,
        "variants": {"fast": ["nuclei", "-silent", "-severity", "critical,high,medium", "-t", "100"],
                     "full": ["nuclei", "-silent", "-severity", "critical,high,medium,low"]},
        "best_for": ["all"],
    },
    "nikto": {
        "speed": "slow",
        "max_time": 120,
        "variants": {"fast": None,  # skip in fast mode
                     "full": ["nikto", "-h", "-Tuning", "1234789"]},
        "best_for": ["apache", "iis", "nginx"],
    },
    "gobuster": {
        "speed": "medium",
        "max_time": 60,
        "variants": {"fast": ["gobuster", "dir", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-q"],
                     "full": ["gobuster", "dir", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-t", "30", "-q"]},
        "best_for": ["all"],
    },
    "ffuf": {
        "speed": "medium",
        "max_time": 60,
        "variants": {"fast": ["ffuf", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20"],
                     "full": ["ffuf", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-t", "30"]},
        "best_for": ["api", "rest"],
    },
    "sqlmap": {
        "speed": "slow",
        "max_time": 180,
        "variants": {"fast": None,
                     "full": ["sqlmap", "--batch", "--random-agent", "--time-sec", "3"]},
        "best_for": ["php", "asp", "jsp", "api"],
    },
    "wpscan": {
        "speed": "medium",
        "max_time": 120,
        "variants": {"fast": ["wpscan", "--no-banner", "-e", "vp"],
                     "full": ["wpscan", "--no-banner", "-e", "vp,vt,tt,u"]},
        "best_for": ["wordpress"],
    },
    "curl": {
        "speed": "fast",
        "max_time": 10,
        "variants": {"fast": ["curl", "-sI"], "full": ["curl", "-sI", "-L"]},
        "best_for": ["all"],
    },
    "httpx": {
        "speed": "fast",
        "max_time": 30,
        "variants": {"fast": ["httpx", "-silent", "-sc", "-title", "-tech-detect"],
                     "full": ["httpx", "-silent", "-sc", "-title", "-tech-detect", "-cname", "-cdn"]},
        "best_for": ["all"],
    },
}


def detect_tech_from_recon(recon_results: dict) -> list:
    """Extract technology hints from recon data to guide tool selection."""
    hints = []
    recon_text = str(recon_results).lower()

    tech_map = {
        "wordpress": "cms",
        "wp-": "cms",
        "wp-content": "cms",
        "wp-json": "cms",
        "drupal": "cms",
        "joomla": "cms",
        # Server types
        "apache": "apache",
        "tomcat": "apache",
        "coyote": "apache",
        "iis": "iis",
        "nginx": "nginx",
        # Languages
        "php": "php",
        "php/": "php",
        "asp.net": "dotnet",
        "aspnet": "dotnet",
        "jsp": "java",
        "java": "java",
        "ruby": "ruby",
        "rails": "ruby",
        "django": "python",
        "flask": "python",
        "python": "python",
        "node": "nodejs",
        "express": "nodejs",
        # API
        "api": "api",
        "rest": "api",
        "graphql": "api",
        "swagger": "api",
        "openapi": "api",
        "json": "api",
    }

    for keyword, tech in tech_map.items():
        if keyword in recon_text:
            hint = f"detected_{tech}"
            if hint not in hints:
                hints.append(hint)

    return hints


def select_tools(available: dict, recon_results: dict,
                 fast: bool = False, verbose: bool = False) -> list:
    """Select the best tools based on target tech + mode.

    Returns list of (tool_name, args, reason, max_time).
    """
    tech_hints = detect_tech_from_recon(recon_results)
    mode = "fast" if fast else "full"

    if verbose:
        print(f"  📋 Tech hints: {tech_hints}")
        print(f"  ⚙️  Mode: {mode}")

    # Always run these (foundational)
    selected = []

    # Phase 1: Always start with fast tools (no AI needed)
    fast_tools = [
        ("whatweb", ["whatweb", "-v"], "Technology fingerprinting", 30),
    ]

    # Only add if available
    for tool_name, args, reason, max_time in fast_tools:
        if tool_name in available:
            profile = TOOL_PROFILES.get(tool_name)
            variant = profile.get("variants", {}).get(mode, profile.get("variants", {}).get("fast"))
            if variant is not None:
                selected.append((tool_name, variant, reason, max_time))

    # Phase 2: Medium tools + fast scans
    medium_tools = []

    # nuclei is always useful
    if "nuclei" in available:
        nuc_args = TOOL_PROFILES["nuclei"]["variants"][mode]
        if nuc_args:
            medium_tools.append(("nuclei", nuc_args, "CVE & vulnerability scanning", 60))

    # gobuster for directory discovery
    if "gobuster" in available:
        gob_args = TOOL_PROFILES["gobuster"]["variants"][mode]
        if gob_args:
            medium_tools.append(("gobuster", gob_args, "Directory enumeration", 60))

    # httpx for tech probing
    if "httpx" in available:
        hx_args = TOOL_PROFILES["httpx"]["variants"][mode]
        if hx_args:
            medium_tools.append(("httpx", hx_args, "HTTP probe + tech detect", 30))

    # Tech-specific tools
    if "wpscan" in available and "detected_cms" in tech_hints:
        wp_args = TOOL_PROFILES["wpscan"]["variants"][mode]
        if wp_args:
            medium_tools.append(("wpscan", wp_args, "WordPress vulnerability scan", 120))

    if "ffuf" in available and "detected_api" in tech_hints:
        ff_args = TOOL_PROFILES["ffuf"]["variants"][mode]
        if ff_args:
            medium_tools.append(("ffuf", ff_args, "API endpoint fuzzing", 60))

    selected.extend(medium_tools)

    # Phase 3: Slow tools (only in full mode, and only if relevant)
    if not fast:
        slow_tools = []

        if "nikto" in available:
            nikto_techs = ["apache", "iis", "nginx"]
            if any(t in tech_hints for t in nikto_techs) or not tech_hints:
                nk_args = TOOL_PROFILES["nikto"]["variants"]["full"]
                if nk_args:
                    slow_tools.append(("nikto", nk_args, "Web server deep scan", 120))

        if "sqlmap" in available and any(t in tech_hints for t in ["php", "java", "dotnet", "api"]):
            sm_args = TOOL_PROFILES["sqlmap"]["variants"]["full"]
            if sm_args:
                slow_tools.append(("sqlmap", sm_args, "SQL injection detection", 180))

        # Add at most 1 slow tool
        if slow_tools:
            selected.append(slow_tools[0])

    if verbose:
        print(f"  🛠️  Selected tools: {[s[0] for s in selected]}")

    return selected
