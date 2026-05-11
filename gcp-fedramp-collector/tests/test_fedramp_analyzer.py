import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


COLLECTOR_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COLLECTOR_ROOT))

from analyzer.fedramp_analyzer import FedRAMPAnalyzer
from analyzer.report_generator import generate_html_report


def analyzer_with_data(data):
    analyzer = FedRAMPAnalyzer("unused")
    analyzer.data = data
    return analyzer


class FedRAMPAnalyzerTests(unittest.TestCase):
    def test_cna_detects_public_sensitive_firewall_rule_from_collector_layout(self):
        analyzer = analyzer_with_data({
            "networking": {
                "networking_resources": {
                    "firewall_rules": [
                        {
                            "name": "allow-admin",
                            "direction": "INGRESS",
                            "sourceRanges": ["10.0.0.0/8", "0.0.0.0/0"],
                            "allowed": [
                                {"IPProtocol": "tcp", "ports": ["22", "443"]}
                            ],
                        }
                    ]
                }
            },
            "compute": {"compute_resources": {"instances": []}},
        })

        analyzer.analyze_ksi_cna()

        findings = analyzer.ksi_results["KSI-CNA"]["findings"]
        self.assertTrue(
            any("22/SSH" in finding["finding"] for finding in findings),
            findings,
        )

    def test_cna_handles_gke_findings_without_firewall_rules(self):
        analyzer = analyzer_with_data({
            "containers": {
                "container_services": {
                    "gke_clusters": [
                        {
                            "name": "cluster-1",
                            "databaseEncryption": {"state": "DECRYPTED"},
                            "bootDiskKmsKey": "GOOGLE_MANAGED",
                        }
                    ]
                }
            }
        })

        analyzer.analyze_ksi_cna()

        findings = analyzer.ksi_results["KSI-CNA"]["findings"]
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("ETCD database not encrypted" in f["finding"] for f in findings))

    def test_cna_only_flags_instances_with_actual_public_ip_configs(self):
        analyzer = analyzer_with_data({
            "compute": {
                "compute_resources": {
                    "instances": [
                        {
                            "name": "private-vm",
                            "networkInterfaces": [{"accessConfigs": []}],
                        },
                        {
                            "name": "public-vm",
                            "networkInterfaces": [
                                {"accessConfigs": [{"natIP": "203.0.113.10"}]}
                            ],
                        },
                    ]
                }
            }
        })

        analyzer.analyze_ksi_cna()

        public_ip_findings = [
            f for f in analyzer.ksi_results["KSI-CNA"]["findings"]
            if "public IP assigned" in f["finding"]
        ]
        self.assertEqual(len(public_ip_findings), 1)
        self.assertIn("public-vm", public_ip_findings[0]["finding"])

    def test_policy_inventory_does_not_penalize_when_old_assets_are_labeled(self):
        analyzer = analyzer_with_data({
            "security": {
                "asset_inventory": [
                    {"name": "resource-1", "labels": {"env": "prod", "owner": "grc"}}
                ]
            }
        })

        analyzer.analyze_ksi_piy()

        result = analyzer.ksi_results["KSI-PIY"]
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["findings"], [])

    def test_recovery_planning_uses_backup_policies_from_new_collector_layout(self):
        analyzer = analyzer_with_data({
            "backup": {
                "backup_build_services": {
                    "backup_policies": [{"name": "nightly-snapshots"}],
                    "compute_snapshots": [],
                    "backup_plans": [],
                }
            },
            "compute": {
                "compute_resources": {
                    "instances": [{"name": "vm-1"}]
                }
            },
        })

        analyzer.analyze_ksi_rpl()

        findings = analyzer.ksi_results["KSI-RPL"]["findings"]
        self.assertFalse(
            any("No automated backup policies configured" in f["finding"] for f in findings),
            findings,
        )

    def test_run_analysis_loads_collector_style_tarball(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            collection_dir = tmp_path / "fedramp_gcp_collection_test-project_20250510_120000"
            iam_dir = collection_dir / "iam"
            iam_dir.mkdir(parents=True)
            (iam_dir / "iam_data.json").write_text(json.dumps({
                "service_accounts": [],
                "iam_policy": {
                    "bindings": [
                        {"role": "roles/editor", "members": ["user:auditor@example.com"]}
                    ]
                },
            }))

            archive_path = tmp_path / "collection.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(collection_dir, arcname=collection_dir.name)

            analyzer = FedRAMPAnalyzer(str(archive_path))
            report = analyzer.run_analysis()

        self.assertIn("KSI-IAM", report["ksi_results"])
        iam_findings = report["ksi_results"]["KSI-IAM"]["findings"]
        self.assertTrue(any("roles/editor" in f["finding"] for f in iam_findings))

    def test_tar_extraction_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = Path(tmpdir) / "bad.tar.gz"
            payload = b"{}"
            with tarfile.open(archive_path, "w:gz") as tar:
                member = tarfile.TarInfo("../evil.json")
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))

            analyzer = FedRAMPAnalyzer(str(archive_path))
            with self.assertRaises(ValueError):
                analyzer.extract_and_load_data()

    def test_compat_report_generator_renders_html(self):
        html = generate_html_report({
            "assessment_date": "2025-05-10T12:00:00",
            "overall_score": 90,
            "summary": {
                "total_findings": 0,
                "critical_findings": 0,
                "ksis_evaluated": 1,
            },
            "ksi_results": {
                "KSI-IAM": {
                    "score": 100,
                    "findings": [],
                    "controls_evaluated": ["AC-2"],
                }
            },
            "recommendations": [],
        })

        self.assertIn("FedRAMP 20x GCP Compliance Assessment Report", html)


if __name__ == "__main__":
    unittest.main()
