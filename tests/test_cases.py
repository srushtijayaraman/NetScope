"""
NetScope X Case Investigation & HTML Forensic Report Unit Tests
Verifies case creation, note appending, artifact attachment, and HTML report generation.
"""

import os
import tempfile
from storage.database import DatabaseManager
from analytics.investigation_manager import generate_case_html_report


def test_case_lifecycle_and_report_generation():
    temp_db_path = os.path.join(tempfile.gettempdir(), f"netscope_case_test_{os.getpid()}.db")
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)

    try:
        db = DatabaseManager(temp_db_path)

        # 1. Create Case
        case = db.create_case(
            case_id="CASE-2026-001",
            title="SYN Flood Investigation against 192.168.1.50",
            summary="Investigating potential half-open connection denial-of-service attack.",
            priority="High",
            status="Open",
            analyst="Lead SecOps",
        )
        assert case["case_id"] == "CASE-2026-001"
        assert case["priority"] == "High"
        assert len(case["notes"]) == 0
        assert len(case["artifacts"]) == 0

        # 2. Add Notes
        n1 = db.add_case_note("CASE-2026-001", "Initial triage: observed 28 standalone TCP SYN packets.", author="Triage Analyst")
        assert n1["id"] is not None
        n2 = db.add_case_note("CASE-2026-001", "Correlated with incident INC-0001; source IP confirmed external.", author="Lead SecOps")
        assert n2["id"] is not None

        # 3. Attach Artifacts
        a1 = db.attach_case_artifact("CASE-2026-001", "incident", "INC-0001", {"category": "DENIAL_OF_SERVICE"})
        assert a1["artifact_id"] == "INC-0001"
        a2 = db.attach_case_artifact("CASE-2026-001", "packet", "14", {"flags": ["SYN"], "port": 80})
        assert a2["artifact_id"] == "14"
        a3 = db.attach_case_artifact("CASE-2026-001", "host", "10.0.0.88", {"role": "Attacker"})
        assert a3["artifact_id"] == "10.0.0.88"

        # 4. Fetch Case
        fetched = db.get_case("CASE-2026-001")
        assert len(fetched["notes"]) == 2
        assert len(fetched["artifacts"]) == 3

        # 5. Update Status
        updated = db.update_case("CASE-2026-001", {"status": "In Progress"})
        assert updated["status"] == "In Progress"

        # 6. Generate Standalone HTML Report & Check XSS Escaping
        malicious_note = "<script>alert('xss')</script>"
        db.add_case_note("CASE-2026-001", malicious_note)
        case_with_xss = db.get_case("CASE-2026-001")

        html_report = generate_case_html_report(case_with_xss)
        assert "<!DOCTYPE html>" in html_report
        assert "CASE-2026-001" in html_report
        assert "SYN Flood Investigation" in html_report
        assert "INC-0001" in html_report
        # Crucial security verification: raw script tag MUST NOT appear unescaped!
        assert "<script>alert('xss')</script>" not in html_report
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_report or "&lt;script&gt;" in html_report

    finally:
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
