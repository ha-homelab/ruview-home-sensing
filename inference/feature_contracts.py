"""Explicit feature selection; recordings and native window geometry stay intact."""

FEATURE_CONTRACT = "native1x64-amplitude-mean-std-abs-slope-v1"
PREFIX_FEATURE_CONTRACT = "native1x64-exclude-wire-pairs-0-1-amplitude-stats-v1"
FEATURE_CONTRACTS = (FEATURE_CONTRACT, PREFIX_FEATURE_CONTRACT)
MODEL_SCHEMAS = {
    FEATURE_CONTRACT: "ruview.native_csi.ridge_candidate.v1",
    PREFIX_FEATURE_CONTRACT: "ruview.native_csi.ridge_prefix_excluded_candidate.v1",
}


def validate_contract(contract):
    if contract not in FEATURE_CONTRACTS:
        raise ValueError("unknown feature contract")
    return contract


def prefix_selection():
    """Return a fresh descriptor: exclusion policy is not inferred sample validity."""
    return {
        "schema": "ruview.csi.feature_selection.v1",
        "feature_contract": PREFIX_FEATURE_CONTRACT,
        "original_wire_pair_indices": list(range(2, 64)),
        "first_word_invalid": None,
        "validity_source": "not_transmitted_by_legacy_firmware",
        "exclusion_basis": "esp32s3_esp_idf_v5.4_first_four_bytes",
    }


def selected_contract(value):
    if not isinstance(value, dict):
        raise ValueError("feature identity must be an object")
    if "feature_selection" not in value:
        return FEATURE_CONTRACT
    selection = value["feature_selection"]
    if (
        not isinstance(selection, dict)
        or selection != prefix_selection()
        or any(type(i) is not int for i in selection["original_wire_pair_indices"])
    ):
        raise ValueError("unknown or changed feature selection")
    return PREFIX_FEATURE_CONTRACT


def validate_prefix_scope(value):
    """Limit the new transform to the admitted native legacy packet layout."""
    if (
        type(value.get("antennas")) is not int
        or value["antennas"] != 1
        or type(value.get("subcarriers")) is not int
        or value["subcarriers"] != 64
        or type(value.get("ppdu_type")) is not int
        or value["ppdu_type"] != 0
        or type(value.get("flags")) is not int
        or value["flags"] not in (0, 0x10)
        or value.get("first_word_invalid") is not None
        or value.get("first_word_sanitized") is not None
    ):
        raise ValueError("prefix exclusion requires the unchanged native legacy grid")
    frequency = value.get("frequency_mhz")
    if (
        type(frequency) is not int
        or not 2412 <= frequency <= 2472
        or (frequency - 2412) % 5
    ):
        raise ValueError("prefix exclusion frequency outside admitted grid")


def pair_indices(contract):
    validate_contract(contract)
    return range(64) if contract == FEATURE_CONTRACT else range(2, 64)


def feature_count(contract):
    return 3 * len(pair_indices(contract))
