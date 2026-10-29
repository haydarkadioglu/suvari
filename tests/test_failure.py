"""Tests for the L0-L5 classification ordering in ``suvari.failure``.

These cover the precedence rule: signature checks run before the L0 success
default, so a long or short failure message is never mistaken for normal
output. They also confirm the L5 duration branch is reachable only for a clean
run that took too long.
"""

from suvari.failure import (
    FALLBACK_MAP,
    FailureLevel,
    classify_failure,
    get_recovery_strategy,
)


def test_permission_forbidden_is_l2() -> None:
    assert classify_failure("curl", "403 Forbidden", 0.3) == FailureLevel.L2_PREREQUISITE


def test_cloudflare_is_l3() -> None:
    assert classify_failure("nmap", "CloudFlare detected", 1.0) == FailureLevel.L3_ENVIRONMENT


def test_http_404_is_l4() -> None:
    assert classify_failure("curl", "HTTP/1.1 404 Not Found", 0.2) == FailureLevel.L4_HYPOTHESIS


def test_success_response_is_l0() -> None:
    assert classify_failure("curl", "HTTP/2 200\nserver: nginx", 0.5) == FailureLevel.L0_OBSERVATION


def test_short_output_still_classified() -> None:
    # <= 10 chars must not bypass the signature chain either.
    assert classify_failure("curl", "403", 0.1) == FailureLevel.L2_PREREQUISITE


def test_uppercase_signature_is_insensitive() -> None:
    assert classify_failure("nmap", "RATE LIMIT HIT BY TARGET", 1.0) == FailureLevel.L3_ENVIRONMENT


def test_empty_output_is_l0() -> None:
    assert classify_failure("curl", "", 0.1) == FailureLevel.L0_OBSERVATION


def test_none_output_is_l0() -> None:
    level = classify_failure("curl", None, 0.1)  # type: ignore[arg-type]
    assert level == FailureLevel.L0_OBSERVATION


def test_none_duration_does_not_crash() -> None:
    level = classify_failure("nmap", "timed out after long wait", None)  # type: ignore[arg-type]
    assert isinstance(level, FailureLevel)
    assert level != FailureLevel.L5_STRATEGY


def test_command_not_found_is_l1() -> None:
    assert classify_failure("nmap", "(error: command not found)", 0.1) == FailureLevel.L1_TOOL_ERROR


def test_timeout_prefix_is_l1() -> None:
    assert classify_failure("nmap", "(TIMEOUT after 60s)", 60.1) == FailureLevel.L1_TOOL_ERROR


def test_error_prefix_without_signature_is_l1() -> None:
    level = classify_failure("nmap", "(error: something odd happened)", 0.2)
    assert level == FailureLevel.L1_TOOL_ERROR


def test_missing_binary_not_found_is_l1() -> None:
    assert classify_failure("nmap", "bash: nmap: not found", 0.1) == FailureLevel.L1_TOOL_ERROR


def test_dns_host_not_found_is_l1() -> None:
    assert classify_failure("dnsrecon", "host not found", 0.1) == FailureLevel.L1_TOOL_ERROR


def test_http_404_not_found_stays_l4() -> None:
    # The bare "not found" L1 signature must not swallow HTTP 404 responses.
    assert classify_failure("curl", "404 page not found", 0.2) == FailureLevel.L4_HYPOTHESIS
    assert classify_failure("curl", "HTTP/1.1 404 Not Found", 0.2) == FailureLevel.L4_HYPOTHESIS


def test_slow_clean_run_is_l5() -> None:
    # The L5 branch is now reachable: a clean run exceeding the duration
    # threshold with no failure signature is classified as a strategy failure.
    level = classify_failure("nmap", "Nmap scan report for 10.0.0.1", 300.0)
    assert level == FailureLevel.L5_STRATEGY


def test_signature_wins_over_duration() -> None:
    assert classify_failure("curl", "403 Forbidden", 300.0) == FailureLevel.L2_PREREQUISITE


def test_recovery_strategy_still_maps() -> None:
    for level in FailureLevel:
        strategy = get_recovery_strategy(level, "nmap")
        assert isinstance(strategy, str)
        assert strategy
    # nmap is in FALLBACK_MAP, so an L1 tool error should suggest a fallback,
    # not "skip".
    assert "nmap" in FALLBACK_MAP
    assert get_recovery_strategy(FailureLevel.L1_TOOL_ERROR, "nmap") != "skip"
