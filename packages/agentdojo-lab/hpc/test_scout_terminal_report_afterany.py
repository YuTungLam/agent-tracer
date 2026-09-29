"""Static contract for the CPU-only nine-job afterany collector."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WRAPPER = ROOT / "scout-terminal-report-afterany.sbatch"
README = ROOT / "README.md"
JOB_IDS = (
    "9123394",
    "9123398",
    "9123399",
    "9126739",
    "9126740",
    "9126776",
    "9129880",
    "9129940",
    "9135588",
)
CASE_IDS = ("A", "B", "C", "C2", "D", "REPEAT", "E", "MULTI", "CONTENT")
DEPENDENCY = "afterany:" + ":".join(JOB_IDS)
EVIDENCE_ROOTS = (
    "runs/scout-case-a-prepared-v6",
    "runs/scout-case-b-prepared-v4",
    "runs/scout-case-c-prepared-v3",
    "runs/scout-case-c2-prepared-v2",
    "runs/scout-case-d-prepared-v2",
    "scout-repeat-judge-20260917-v1",
    "runs/scout-case-e-prepared-v1",
    "scout-multi-repeat-judge-20260917-v1",
    "scout-content-composition-argument-20260917-v1",
)
TERMINAL_NAMES = (
    "scout-case-a-20260917-v4/case-a-batch-summary.json",
    "scout-case-b-20260917-v3/case-b-batch-summary.json",
    "scout-case-c-20260917-v3/case-c-batch-summary.json",
    "scout-case-c2-20260917-v1/case-c2-batch-summary.json",
    "scout-case-d-20260917-v1/case-d-batch-summary.json",
    "scout-repeat-judge-smoke-20260917-v1/repeat-judge-batch-summary.json",
    "scout-case-e-20260917-v1/case-e-batch-summary.json",
    "scout-multi-repeat-judge-smoke-20260917-v1/multi-repeat-judge-batch-summary.json",
    "scout-content-composition-argument-smoke-20260917-v1.content-composition-argument-batch-summary.json",
)


class AfteranyCollectorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")

    def test_cpu_only_minimal_genoa_resources(self) -> None:
        expected = {
            "#SBATCH --account=uoa04799",
            "#SBATCH --partition=genoa",
            "#SBATCH --nodes=1",
            "#SBATCH --ntasks=1",
            "#SBATCH --cpus-per-task=1",
            "#SBATCH --mem=2G",
            "#SBATCH --time=00:10:00",
            "#SBATCH --no-requeue",
        }
        self.assertTrue(expected.issubset(set(self.wrapper.splitlines())))
        self.assertIn(f"#SBATCH --dependency={DEPENDENCY}", self.wrapper)
        lowered = self.wrapper.lower()
        for forbidden in ("#sbatch --gpu", "#sbatch --gres", "nvidia-smi", "cuda_visible"):
            self.assertNotIn(forbidden, lowered)

    def test_strict_shell_and_immutable_bundle_gates(self) -> None:
        self.assertIn("set -euo pipefail", self.wrapper)
        self.assertIn("umask 077", self.wrapper)
        self.assertIn("scout-terminal-collector-submission-20260917-v1", self.wrapper)
        self.assertIn("SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256", self.wrapper)
        self.assertIn("sha256sum --check --strict --status", self.wrapper)
        self.assertIn("cmp --silent", self.wrapper)
        self.assertIn('find "$COLLECTOR_BUNDLE" -type l', self.wrapper)
        self.assertIn('find "$COLLECTOR_BUNDLE" -type f -perm /0222', self.wrapper)
        for required in (
            "hpc/scout-terminal-report-afterany.sbatch",
            "scripts/report_scout_terminal_panel.py",
            "src/agentdojo_lab/scout_terminal_report.py",
            "reports/20260916-meeting-packet-v1/deliverables.json",
        ):
            self.assertIn(required, self.wrapper)
        self.assertIn("sys.version_info[:2] == (3, 12)", self.wrapper)

    def test_all_nine_exact_evidence_and_terminal_bindings(self) -> None:
        for case_id, evidence, terminal in zip(CASE_IDS, EVIDENCE_ROOTS, TERMINAL_NAMES, strict=True):
            self.assertEqual(self.wrapper.count(f'--evidence "{case_id}='), 1)
            self.assertEqual(self.wrapper.count(f'--terminal "{case_id}='), 1)
            self.assertIn(evidence, self.wrapper)
            self.assertIn(terminal, self.wrapper)
        self.assertIn("scout-content-composition-argument-20260917-v1\n", self.wrapper)
        self.assertIn(
            "scout-content-composition-argument-smoke-20260917-v1.content-composition-argument-batch-summary.json",
            self.wrapper,
        )

    def test_missing_inputs_are_passed_and_output_is_fresh_and_disjoint(self) -> None:
        self.assertNotIn('[[ -e "$input_path"', self.wrapper)
        self.assertNotIn('[[ -f "$input_path"', self.wrapper)
        self.assertNotIn('[[ -d "$input_path"', self.wrapper)
        self.assertIn('[[ ! -e "$COLLECTOR_OUTPUT" && ! -L "$COLLECTOR_OUTPUT" ]]', self.wrapper)
        self.assertIn("paths_overlap", self.wrapper)
        self.assertIn('paths_overlap "$COLLECTOR_OUTPUT" "$input_path"', self.wrapper)
        self.assertIn('paths_overlap "$COLLECTOR_OUTPUT" "$protected_path"', self.wrapper)
        self.assertIn("scout-terminal-panel-20260917-v1", self.wrapper)
        self.assertNotIn("--plan-only", self.wrapper)

    def test_collector_has_no_model_network_native_or_scheduler_queries(self) -> None:
        executable = "\n".join(
            line for line in self.wrapper.splitlines() if not line.lstrip().startswith("#")
        ).lower()
        for forbidden in (
            "squeue",
            "sacct",
            "scontrol",
            "sbatch ",
            "curl ",
            "wget ",
            "http://",
            "https://",
            "run_case_",
            "native_smoke",
        ):
            self.assertNotIn(forbidden, executable)
        self.assertIn("HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1", self.wrapper)

    def test_readme_has_exact_afterany_submission_and_fresh_logs(self) -> None:
        self.assertIn(f"--dependency={DEPENDENCY}", self.readme)
        self.assertIn(
            "--output=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/"
            "scout-terminal-panel-afterany-20260917-v1-%j.out",
            self.readme,
        )
        self.assertIn(
            "--error=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/"
            "scout-terminal-panel-afterany-20260917-v1-%j.err",
            self.readme,
        )
        self.assertIn(
            "/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/"
            "scout-terminal-collector-submission-20260917-v1/hpc/"
            "scout-terminal-report-afterany.sbatch",
            self.readme,
        )


if __name__ == "__main__":
    unittest.main()
