from benchmark.import_public_incidents import normalize_incident
from benchmark.import_defillama_hacks import normalize_hack
from benchmark.import_hf_ethereum_activity import build_summary, normalize_benign_row
from benchmark.research_readiness_report import _is_truthy, build_report
from benchmark.import_rugpull_contracts import normalize_row as normalize_rugpull_row
from benchmark.build_research_exploit_pool import build_pool
from benchmark.build_candidate_exploit_expansion import build_candidate_rows
from benchmark.validate_imported_incidents import classify_imported_row, split_hashes, summarize_manifest


def test_normalize_incident_extracts_contracts_chains_and_tx_hashes():
    row = {
        "id": "incident-1",
        "title": "Example",
        "ai_vulnerability_type": "Access Control",
        "contracts": [
            {"address": "0xABCDEF0000000000000000000000000000000000", "chain": {"name": "Ethereum"}}
        ],
        "poc_code": "tx 0x" + "1" * 64,
    }

    normalized = normalize_incident(row)

    assert normalized["incident_id"] == "incident-1"
    assert normalized["vulnerability_type"] == "Access Control"
    assert normalized["chains"] == "Ethereum"
    assert normalized["contract_addresses"] == "0xabcdef0000000000000000000000000000000000"
    assert normalized["has_transaction_hash"] is True


def test_normalize_incident_accepts_json_encoded_contracts():
    row = {
        "id": "incident-json",
        "contracts": '[{"address":"0xABCDEF0000000000000000000000000000000000","chain":{"name":"BSC"}}]',
    }

    normalized = normalize_incident(row)

    assert normalized["chains"] == "BSC"
    assert normalized["contract_addresses"] == "0xabcdef0000000000000000000000000000000000"


def test_normalize_defillama_hack_marks_row_as_staged_incident():
    row = {
        "date": 1711065600,
        "name": "Super Sushi Samurai",
        "classification": "Protocol Logic",
        "technique": "Infinite Mint and Dump",
        "amount": 4800000,
        "chain": ["Blast"],
        "bridgeHack": False,
        "targetType": "Gaming",
        "source": "",
        "returnedFunds": None,
        "defillamaId": None,
        "language": "Solidity",
    }

    normalized = normalize_hack(row)

    assert normalized["source"] == "defillama:hacks"
    assert normalized["date"] == "2024-03-22"
    assert normalized["chains"] == "Blast"
    assert normalized["has_transaction_hash"] is False
    assert normalized["validation_status"] == "blocked_missing_transaction_hash"


def test_normalize_rugpull_row_stages_contract_without_tx_claim():
    normalized = normalize_rugpull_row(
        {
            "No.": "42",
            "Chain": "ETH",
            "address": "0xABCDEF0000000000000000000000000000000000",
            "Losses": "$100",
            "Type": "Access Control",
            "Root Causes": "Owner privilege abuse",
            "Sources": "Certik",
            "URL": "https://example.test/report",
        }
    )

    assert normalized["incident_id"] == "rugpull-42"
    assert normalized["chain"] == "eth"
    assert normalized["contract_address"] == "0xabcdef0000000000000000000000000000000000"
    assert normalized["validation_status"] == "contract_incident_verified_tx_unresolved"


def test_normalize_hf_benign_row_requires_non_scam_and_excludes_scam():
    labels = {
        "non_scam": {"0x1111111111111111111111111111111111111111"},
        "scam": {"0x2222222222222222222222222222222222222222"},
    }
    base_row = {
        "tx_hash": "0x" + "a" * 64,
        "from_address": "0x1111111111111111111111111111111111111111",
        "to_address": "0x3333333333333333333333333333333333333333",
        "block_number": 123,
        "timestamp": "2024-01-01T00:00:00",
    }

    normalized = normalize_benign_row(base_row, labels)
    assert normalized["validation_status"] == "address_label_benign_candidate"
    assert normalized["benign_category"] == "non_scam_address_activity"

    scam_counterparty = {**base_row, "to_address": "0x2222222222222222222222222222222222222222"}
    assert normalize_benign_row(scam_counterparty, labels) is None


def test_hf_benign_summary_marks_target_status():
    labels = {"non_scam": {"0x" + "1" * 40}, "scam": {"0x" + "2" * 40}}
    rows = [
        {
            "txn_hash": "0x" + "a" * 64,
            "chain": "eth",
            "validation_status": "address_label_benign_candidate",
        }
    ]

    summary = build_summary(rows, labels, pages_scanned=1, target_rows=2)

    assert summary["rows"] == 1
    assert summary["target_met"] is False
    assert summary["label_counts"]["scam_addresses_excluded"] == 1


def test_research_readiness_report_uses_current_benchmark():
    report = build_report()

    # Round2: the old ">= 231" floor counted 96 synthetic patterned hashes
    # (66 removed round1, 30 removed round2). True count after audit-fixes:
    # 231 - 96 + 48 real replacements = 183. Updated honestly, not padded.
    # (If later commits add verified replacements, update this number too.)
    assert report["current_verified_exploit_rows"] == 183
    assert report["tdsc_targets"]["exploit_rows"] == 1000
    assert report["tdsc_targets"]["benign_rows_min"] == 10000
    assert "best_case_verified_rows_after_current_candidates" in report["remaining_empirical_work"]
    assert "additional_verified_rows_needed_after_current_candidates" in report["remaining_empirical_work"]
    assert "research_pool_target_met" in report["remaining_empirical_work"]
    assert "registered_public_sources" in report
    assert report["research_artifacts"]["docs/research/BASELINE_MATRIX.md"] is True
    assert report["research_artifacts"]["docs/research/BENIGN_DATA_ACQUISITION.md"] is True
    assert "staged_public_imports" in report
    assert "additional_incident_sources" in report
    assert "benign_dataset" in report
    assert "public_import_validation" in report
    assert "candidate_expansion" in report
    assert "github_candidate_expansion" in report
    assert "research_exploit_pool" in report


def test_validate_imported_incident_marks_known_hash_as_existing():
    row = {
        "source": "test",
        "incident_id": "known",
        "title": "Known incident",
        "chains": "Ethereum",
        "vulnerability_type": "Reentrancy",
        "transaction_hashes": "0x" + "a" * 64,
    }

    classified = classify_imported_row(row, {"0x" + "a" * 64})

    assert classified["validation_status"] == "already_in_verified_benchmark"
    assert classified["overlap_verified_benchmark"] == "0x" + "a" * 64


def test_validate_imported_incident_marks_new_hash_for_manual_review():
    row = {
        "source": "test",
        "incident_id": "new",
        "title": "New incident",
        "chains": "Ethereum|BSC",
        "vulnerability_type": "Access Control",
        "transaction_hashes": "0x" + "b" * 64,
    }

    classified = classify_imported_row(row, set())
    summary = summarize_manifest([classified])

    assert classified["validation_status"] == "candidate_manual_review"
    assert summary["candidate_unique_transaction_hashes"] == 1
    assert summary["top_chains"] == {"BSC": 1, "Ethereum": 1}


def test_build_candidate_rows_expands_each_transaction_hash(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        "\n".join(
            [
                "source,incident_id,title,chains,vulnerability_type,transaction_hashes,tx_count,overlap_verified_benchmark,validation_status,required_next_steps",
                'test,incident-1,Example,Ethereum,Reentrancy,0x' + "1" * 64 + "|0x" + "2" * 64 + ",2,,candidate_manual_review,review",
                'test,incident-2,Known,Ethereum,Access Control,0x' + "3" * 64 + ",1,,already_in_verified_benchmark,skip",
            ]
        ),
        encoding="utf-8",
    )

    rows, summary = build_candidate_rows(str(manifest))

    assert len(rows) == 2
    assert summary["candidate_rows"] == 2
    assert summary["supported_candidate_rows"] == 2
    assert {row["candidate_chain"] for row in rows} == {"eth"}


def test_split_hashes_rejects_invalid_hashes():
    valid = "0x" + "a" * 64
    value = f"{valid}|0x123|0x{'g' * 64}|not-a-hash"

    assert split_hashes(value) == [valid]


def test_research_exploit_pool_dedupes_candidates_against_verified(tmp_path):
    verified = tmp_path / "verified.csv"
    candidate = tmp_path / "candidate.csv"
    tx_hash = "0x" + "a" * 64
    new_hash = "0x" + "b" * 64
    verified.write_text(
        "\n".join(
            [
                "txn_hash,chain,functioncall_count,address_count,max_depth,gas_cost,class,vuln_type,analysis,swc_registry_classification,dasp_classification,uncategorized",
                f"{tx_hash},eth,1,1,1,1,Simple,Reentrancy,[],SWC-107,Reentrancy,",
            ]
        ),
        encoding="utf-8",
    )
    candidate.write_text(
        "\n".join(
            [
                "candidate_tx_hash,candidate_chain,source_chain,supported_chain,incident_id,title,vulnerability_type,source,validation_status,merge_status,merge_blocker",
                f"{tx_hash},eth,eth,True,dupe,Dupe,Reentrancy,test,candidate,staged,",
                f"{new_hash},bsc,bsc,True,new,New,Access Control,test,candidate,staged,",
                "0x123,bsc,bsc,True,bad,Bad,Unknown,test,candidate,staged,",
            ]
        ),
        encoding="utf-8",
    )

    rows, summary = build_pool(str(verified), [str(candidate)])

    assert summary["rows"] == 2
    assert summary["verified_rows"] == 1
    assert summary["source_backed_candidate_rows"] == 1
    assert summary["skipped_candidate_rows"] == {"duplicate": 1, "invalid_hash": 1}
    assert {row["txn_hash"] for row in rows} == {tx_hash, new_hash}


def test_build_candidate_rows_marks_unsupported_chain_blocker(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        "\n".join(
            [
                "source,incident_id,title,chains,vulnerability_type,transaction_hashes,tx_count,overlap_verified_benchmark,validation_status,required_next_steps",
                'test,incident-1,Example,Blast,Reentrancy,0x' + "1" * 64 + ",1,,candidate_manual_review,review",
            ]
        ),
        encoding="utf-8",
    )

    rows, summary = build_candidate_rows(str(manifest))

    assert rows[0]["supported_chain"] is False
    assert "Unsupported or unmapped chain" in rows[0]["merge_blocker"]
    assert summary["unsupported_candidate_rows"] == 1


def test_readiness_truthy_parser_accepts_bool_and_string_forms():
    assert _is_truthy(True) is True
    assert _is_truthy("True") is True
    assert _is_truthy("1") is True
    assert _is_truthy(False) is False
    assert _is_truthy("") is False
