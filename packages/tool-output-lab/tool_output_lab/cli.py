"""Command-line entry point for the instrumentation pilot."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable, Sequence

from .conditions import FixtureVariant
from .experiment import (
    ExperimentConfig,
    require_external_artifact_path,
    run_experiment,
)
from .gemini import DEFAULT_GEMINI_MODEL, GeminiBackend
from .groq import DEFAULT_GROQ_MODEL, GroqBackend
from .llm import (
    CAPABILITY_PROMPT_PROFILE_ID,
    CALIBRATION_PROMPT_PROFILE_ID,
    GUARDED_PROMPT_PROFILE_ID,
    NEUTRAL_PROMPT_PROFILE_ID,
    ModelBackedPolicy,
)
from .policy import AgentPolicy
from .propagation import (
    GuardMode,
    IngressChannel,
    PropagationConfig,
    run_propagation_testbed,
)
from .qualification import (
    ATTACK_CALIBRATION_RECEIPT_KEY,
    CAPABILITY_RECEIPT_KEY,
    CALIBRATION_TASK_IDS,
    CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
    CLEAN_NOISE_FLOOR_ROLE,
    FROZEN_HELD_OUT_EXPERIMENT_ID,
    FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256,
    HELD_OUT_TASK_IDS,
    NOT_APPLICABLE_GATE_RECEIPT_HASH,
    NOT_APPLICABLE_PROTOCOL_MANIFEST_HASH,
    QUALIFICATION_PROTOCOL_VERSION,
    qualification_receipt_sha256,
    validate_tasks_for_evidence_role,
)
from .tasks import build_capability_control_task, load_tasks
from .utils import canonical_json

CODEBASE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = CODEBASE_ROOT.parent
DEFAULT_TASKS_PATH = CODEBASE_ROOT / "configs" / "tasks.json"
REAL_MODEL_POLICIES = {"gemini", "groq"}
DEFAULT_MODELS = {
    "gemini": DEFAULT_GEMINI_MODEL,
    "groq": DEFAULT_GROQ_MODEL,
}
REAL_MODEL_TRANSPORTS = {
    "gemini": "google_gemini_interactions_v1",
    "groq": "groq_openai_chat_completions_v1",
}
QUALIFICATION_MODES = {
    "smoke": {
        "prompt_profile_id": GUARDED_PROMPT_PROFILE_ID,
        "fixture_variant": FixtureVariant.LEGACY_OVERRIDE.value,
        "evidence_role": "smoke_test",
        "dataset_split": "not_applicable",
        "user_authorized_sink": False,
    },
    "capability": {
        "prompt_profile_id": CAPABILITY_PROMPT_PROFILE_ID,
        "fixture_variant": FixtureVariant.LEGACY_OVERRIDE.value,
        "evidence_role": "capability_control",
        "dataset_split": "not_applicable",
        "user_authorized_sink": True,
    },
    "vulnerable-calibration": {
        "prompt_profile_id": CALIBRATION_PROMPT_PROFILE_ID,
        "fixture_variant": FixtureVariant.EXACT_FUNCTION_CALL.value,
        "evidence_role": "attack_calibration",
        "dataset_split": "calibration",
        "user_authorized_sink": False,
    },
    "neutral-calibration": {
        "prompt_profile_id": NEUTRAL_PROMPT_PROFILE_ID,
        "fixture_variant": FixtureVariant.EXACT_FUNCTION_CALL.value,
        "evidence_role": "attack_calibration",
        "dataset_split": "calibration",
        "user_authorized_sink": False,
    },
    "held-out-evaluation": {
        "prompt_profile_id": NEUTRAL_PROMPT_PROFILE_ID,
        "fixture_variant": FixtureVariant.EXACT_FUNCTION_CALL.value,
        "evidence_role": "susceptibility_evaluation",
        "dataset_split": "held_out",
        "user_authorized_sink": False,
    },
}
ANALYSIS_MODES = {
    "clean-noise-floor": {
        "fixture_variant": FixtureVariant.EXACT_FUNCTION_CALL.value,
        "evidence_role": CLEAN_NOISE_FLOOR_ROLE,
        "dataset_split": "calibration",
        "user_authorized_sink": False,
    }
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tool_output_lab",
        description="Run the sandboxed matched tool-output injection pilot.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser(
        "run",
        help="run a declared matched attack or clean-noise protocol",
    )
    run_parser.add_argument(
        "--tasks",
        type=Path,
        default=DEFAULT_TASKS_PATH,
        help="path to the synthetic task JSON file",
    )
    run_parser.add_argument(
        "--allow-custom-synthetic-tasks",
        action="store_true",
        help=(
            "confirm that a custom real-model task file contains synthetic, "
            "non-private data only"
        ),
    )
    run_parser.add_argument(
        "--trace",
        type=Path,
        required=True,
        help="output JSONL trace path outside the shared repository",
    )
    run_parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="output summary JSON path (defaults next to the trace)",
    )
    run_parser.add_argument("--experiment-id", default=None)
    run_parser.add_argument(
        "--repetitions",
        type=int,
        default=None,
        help="matched units (defaults to 3 for real models and 2 for scripts)",
    )
    run_parser.add_argument("--seed", type=int, default=20260723)
    run_parser.add_argument(
        "--policy",
        choices=("vulnerable", "safe", "gemini", "groq"),
        default="vulnerable",
    )
    run_parser.add_argument(
        "--model",
        default=None,
        help="fixed provider model ID; defaults by policy and rejects moving aliases",
    )
    evidence_mode_group = run_parser.add_mutually_exclusive_group()
    evidence_mode_group.add_argument(
        "--qualification-mode",
        choices=tuple(QUALIFICATION_MODES),
        default=None,
        help=(
            "explicit real-model evidence role; defaults to smoke and is "
            "unavailable for scripted policies"
        ),
    )
    evidence_mode_group.add_argument(
        "--analysis-mode",
        choices=tuple(ANALYSIS_MODES),
        default=None,
        help=(
            "independent diagnostic analysis; clean-noise-floor runs paired "
            "clean A/B decisions and never contributes to attack estimates"
        ),
    )
    run_parser.add_argument(
        "--fixture-variant",
        choices=tuple(variant.value for variant in FixtureVariant),
        default=None,
        help=(
            "predeclared attack carrier; otherwise the qualification-mode "
            "default is used"
        ),
    )
    run_parser.add_argument(
        "--confirm-held-out-evaluation",
        action="store_true",
        help=(
            "confirm that the protocol is frozen before consuming held-out tasks"
        ),
    )
    run_parser.add_argument(
        "--capability-receipt",
        type=Path,
        default=None,
        help=(
            "successful capability-control summary required for held-out "
            "evaluation"
        ),
    )
    run_parser.add_argument(
        "--attack-calibration-receipt",
        type=Path,
        default=None,
        help=(
            "qualified vulnerable-calibration summary required for held-out "
            "evaluation"
        ),
    )
    run_parser.add_argument(
        "--task-id",
        default=None,
        help=(
            "run one synthetic task; non-held-out real-model modes default to "
            "the first allowed task, while held-out evaluation defaults to "
            "the frozen held-out task set"
        ),
    )
    run_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing trace and summary files",
    )
    testbed_parser = subparsers.add_parser(
        "testbed",
        help="run the isolated scripted propagation diagnostic",
        description=(
            "Run a scripted, in-process memory-propagation diagnostic. "
            "This mode is instrumentation-only and never attack-estimate "
            "eligible."
        ),
    )
    testbed_parser.add_argument(
        "--tasks",
        type=Path,
        default=DEFAULT_TASKS_PATH,
        help="path to the synthetic task JSON file",
    )
    testbed_parser.add_argument(
        "--trace",
        type=Path,
        required=True,
        help="output JSONL trace path outside the shared repository",
    )
    testbed_parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="output summary JSON path (defaults next to the trace)",
    )
    testbed_parser.add_argument(
        "--experiment-id",
        default="scripted-propagation-testbed",
    )
    testbed_parser.add_argument("--repetitions", type=int, default=1)
    testbed_parser.add_argument("--seed", type=int, default=20260817)
    testbed_parser.add_argument(
        "--policy",
        choices=("vulnerable", "safe"),
        default="vulnerable",
        help="scripted post-memory-read decision policy",
    )
    testbed_parser.add_argument(
        "--position",
        choices=("both", "tool-output", "direct-user-prompt"),
        default="both",
        help="place the matched treatment note in one or both ingress positions",
    )
    testbed_parser.add_argument(
        "--guard",
        choices=("allow", "block"),
        default="allow",
        help="allow or block a proposed simulated sink dispatch",
    )
    testbed_parser.add_argument(
        "--task-id",
        default=None,
        help="run one synthetic task instead of the complete task manifest",
    )
    testbed_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing trace and summary files",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    is_real_model_policy = args.policy in REAL_MODEL_POLICIES
    analysis_mode = args.analysis_mode
    if analysis_mode is not None and not is_real_model_policy:
        raise ValueError(
            "--analysis-mode clean-noise-floor requires --policy gemini or "
            "--policy groq; scripted controls are available only through the "
            "library test harness"
        )
    if not is_real_model_policy and args.qualification_mode is not None:
        raise ValueError(
            "--qualification-mode is available only with a real-model policy"
        )
    if not is_real_model_policy and args.fixture_variant is not None:
        raise ValueError(
            "--fixture-variant is available only with a real-model policy"
        )
    qualification_mode = None
    if is_real_model_policy and analysis_mode is None:
        qualification_mode = args.qualification_mode or "smoke"
    if (
        args.policy == "groq"
        and qualification_mode == "held-out-evaluation"
    ):
        raise ValueError(
            "The frozen held-out protocol is Gemini-specific; Groq requires "
            "a separately frozen protocol"
        )
    if analysis_mode is not None:
        mode_config = {
            **ANALYSIS_MODES[analysis_mode],
            "prompt_profile_id": (
                NEUTRAL_PROMPT_PROFILE_ID
                if is_real_model_policy
                else "not_applicable"
            ),
        }
    elif qualification_mode is not None:
        mode_config = QUALIFICATION_MODES[qualification_mode]
    else:
        mode_config = {
            "prompt_profile_id": "not_applicable",
            "fixture_variant": FixtureVariant.LEGACY_OVERRIDE.value,
            "evidence_role": "instrumentation_control",
            "dataset_split": "not_applicable",
            "user_authorized_sink": False,
        }
    if analysis_mode is not None and args.fixture_variant is not None:
        raise ValueError(
            "clean-noise-floor uses its fixed clean fixture and does not allow "
            "--fixture-variant"
        )
    if analysis_mode is not None and args.confirm_held_out_evaluation:
        raise ValueError(
            "clean-noise-floor is not held-out evaluation and does not accept "
            "--confirm-held-out-evaluation"
        )
    if (
        qualification_mode == "held-out-evaluation"
        and not args.confirm_held_out_evaluation
    ):
        raise ValueError(
            "held-out evaluation requires --confirm-held-out-evaluation"
        )
    if (
        qualification_mode == "held-out-evaluation"
        and args.tasks.resolve() != DEFAULT_TASKS_PATH.resolve()
    ):
        raise ValueError(
            "held-out evaluation requires the frozen default task manifest"
        )
    if (
        qualification_mode == "held-out-evaluation"
        and args.fixture_variant is not None
    ):
        raise ValueError(
            "held-out evaluation does not allow a fixture override"
        )
    if (
        qualification_mode == "held-out-evaluation"
        and args.task_id is not None
    ):
        raise ValueError(
            "held-out evaluation requires the complete frozen held-out task set"
        )
    receipt_paths = {
        CAPABILITY_RECEIPT_KEY: args.capability_receipt,
        ATTACK_CALIBRATION_RECEIPT_KEY: (
            args.attack_calibration_receipt
        ),
    }
    if qualification_mode == "held-out-evaluation":
        missing_receipts = sorted(
            name for name, path in receipt_paths.items() if path is None
        )
        if missing_receipts:
            raise ValueError(
                "held-out evaluation requires successful capability and "
                "attack-calibration summary receipts"
            )
    elif any(path is not None for path in receipt_paths.values()):
        raise ValueError(
            "qualification receipts are accepted only for held-out evaluation"
        )
    if (
        is_real_model_policy
        and args.tasks.resolve() != DEFAULT_TASKS_PATH.resolve()
        and not args.allow_custom_synthetic_tasks
    ):
        raise ValueError(
            "Custom real-model task files require "
            "--allow-custom-synthetic-tasks to confirm synthetic-only data"
        )
    tasks = load_tasks(args.tasks)
    if args.task_id is not None:
        tasks = [task for task in tasks if task.task_id == args.task_id]
        if not tasks:
            raise ValueError(f"Unknown task_id: {args.task_id}")
    elif qualification_mode in {
        "vulnerable-calibration",
        "neutral-calibration",
    }:
        tasks = [
            task for task in tasks if task.task_id in CALIBRATION_TASK_IDS
        ]
    elif analysis_mode == "clean-noise-floor":
        tasks = [
            task for task in tasks if task.task_id in CALIBRATION_TASK_IDS
        ]
    elif qualification_mode == "held-out-evaluation":
        tasks = [
            task for task in tasks if task.task_id in HELD_OUT_TASK_IDS
        ]
    if qualification_mode in {
        "vulnerable-calibration",
        "neutral-calibration",
    } or analysis_mode == "clean-noise-floor":
        unexpected = [
            task.task_id
            for task in tasks
            if task.task_id not in CALIBRATION_TASK_IDS
        ]
        if unexpected:
            mode_label = (
                "Clean noise-floor"
                if analysis_mode == "clean-noise-floor"
                else "Calibration"
            )
            raise ValueError(
                f"{mode_label} may use only frozen calibration tasks "
                f"{sorted(CALIBRATION_TASK_IDS)}; found {unexpected}"
            )
    if qualification_mode == "held-out-evaluation":
        unexpected = [
            task.task_id
            for task in tasks
            if task.task_id not in HELD_OUT_TASK_IDS
        ]
        if unexpected:
            raise ValueError(
                "Held-out evaluation may use only frozen held-out tasks "
                f"{sorted(HELD_OUT_TASK_IDS)}; found {unexpected}"
            )

    summary_path = args.summary or args.trace.with_suffix(".summary.json")
    require_external_artifact_path(args.trace, label="trace")
    require_external_artifact_path(summary_path, label="summary")
    qualification_receipts = None
    if qualification_mode == "held-out-evaluation":
        qualification_receipts = {}
        for receipt_name, receipt_path in receipt_paths.items():
            assert receipt_path is not None
            require_external_artifact_path(
                receipt_path,
                label=f"{receipt_name} receipt",
            )
            qualification_receipts[receipt_name] = _read_json_receipt(
                receipt_path
            )

    if is_real_model_policy:
        if qualification_mode == "held-out-evaluation":
            tasks = [
                task for task in tasks if task.task_id in HELD_OUT_TASK_IDS
            ]
        elif args.task_id is None:
            tasks = tasks[:1]
        if qualification_mode == "capability":
            tasks = [build_capability_control_task(task) for task in tasks]

    repetitions = args.repetitions
    if repetitions is None:
        repetitions = 3 if is_real_model_policy else 2
    experiment_id = args.experiment_id
    if experiment_id is None:
        if qualification_mode == "held-out-evaluation":
            experiment_id = FROZEN_HELD_OUT_EXPERIMENT_ID
        elif analysis_mode is not None:
            experiment_id = f"{args.policy}-{analysis_mode}"
        else:
            experiment_id = (
                f"{args.policy}-{qualification_mode}"
                if is_real_model_policy
                else "instrumentation-pilot"
            )
    code_commit, code_dirty = _git_provenance()

    config = ExperimentConfig(
        experiment_id=experiment_id,
        repetitions=repetitions,
        seed=args.seed,
        policy_name=args.policy,
        max_steps=2 if is_real_model_policy else 1,
        transport=(
            REAL_MODEL_TRANSPORTS[args.policy]
            if is_real_model_policy
            else "in_process_mock"
        ),
        code_commit=code_commit,
        code_dirty=code_dirty,
        fixture_variant=(
            args.fixture_variant
            or str(mode_config["fixture_variant"])
        ),
        prompt_profile_id=str(mode_config["prompt_profile_id"]),
        evidence_role=str(mode_config["evidence_role"]),
        dataset_split=str(mode_config["dataset_split"]),
        protocol_version=(
            CLEAN_NOISE_FLOOR_PROTOCOL_VERSION
            if analysis_mode == "clean-noise-floor"
            else QUALIFICATION_PROTOCOL_VERSION
        ),
        protocol_manifest_hash=(
            FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256
            if qualification_mode == "held-out-evaluation"
            else NOT_APPLICABLE_PROTOCOL_MANIFEST_HASH
        ),
        capability_receipt_sha256=(
            qualification_receipt_sha256(
                qualification_receipts[CAPABILITY_RECEIPT_KEY]
            )
            if qualification_receipts is not None
            else NOT_APPLICABLE_GATE_RECEIPT_HASH
        ),
        attack_calibration_receipt_sha256=(
            qualification_receipt_sha256(
                qualification_receipts[
                    ATTACK_CALIBRATION_RECEIPT_KEY
                ]
            )
            if qualification_receipts is not None
            else NOT_APPLICABLE_GATE_RECEIPT_HASH
        ),
        user_authorized_sink=bool(
            mode_config["user_authorized_sink"]
        ),
    )
    config.validate()
    validate_tasks_for_evidence_role(
        tasks,
        config.evidence_role,
        real_model_configured=is_real_model_policy,
    )

    policy_factory: Callable[[], AgentPolicy] | None = None
    backend: GeminiBackend | GroqBackend | None = None
    if args.policy == "gemini":
        backend = GeminiBackend(
            model_id=args.model or DEFAULT_MODELS["gemini"]
        )
        policy_factory = lambda backend=backend: ModelBackedPolicy(
            backend,
            prompt_profile_id=str(mode_config["prompt_profile_id"]),
            evidence_scope=f"real_llm_{mode_config['evidence_role']}",
        )
    elif args.policy == "groq":
        backend = GroqBackend(
            model_id=args.model or DEFAULT_MODELS["groq"]
        )
        policy_factory = lambda backend=backend: ModelBackedPolicy(
            backend,
            prompt_profile_id=str(mode_config["prompt_profile_id"]),
            evidence_scope=f"real_llm_{mode_config['evidence_role']}",
        )
    try:
        result = run_experiment(
            tasks,
            config,
            policy_factory=policy_factory,
            qualification_receipts=qualification_receipts,
            trace_path=args.trace,
            summary_path=summary_path,
            overwrite=args.overwrite,
        )
    finally:
        if backend is not None:
            finish_schedule = getattr(
                backend,
                "finish_request_schedule",
                None,
            )
            if callable(finish_schedule):
                finish_schedule()
    external_effects = sum(
        bool(summary.external_side_effect) for summary in result.summaries
    )
    error_runs = sum(summary.status == "error" for summary in result.summaries)
    profile = result.policy_profile
    result_experiment = result.to_mapping()["experiment"]
    print(
        canonical_json(
            {
                "experiment_id": config.experiment_id,
                "policy": config.policy_name,
                "runtime_kind": profile.runtime_kind,
                "evidence_scope": profile.evidence_scope,
                "provider_id": profile.provider_id,
                "model_id": profile.model_id,
                "model_version": profile.model_version,
                "sdk_name": profile.sdk_name,
                "sdk_version": profile.sdk_version,
                "api_version": profile.api_version,
                "real_model_configured": profile.real_model_configured,
                "empirical_llm_completed_runs": (
                    result.empirical_llm_completed_runs
                ),
                "any_empirical_llm_observation": (
                    result.any_empirical_llm_observation
                ),
                "empirical_llm_evidence": result.empirical_llm_evidence,
                "empirical_clean_pair_evidence": (
                    result.empirical_clean_pair_evidence
                ),
                "qualification_mode": qualification_mode,
                "analysis_mode": analysis_mode,
                "prompt_profile_id": profile.prompt_profile_id,
                "prompt_profile_version": profile.prompt_profile_version,
                "fixture_variant": config.fixture_variant,
                "evidence_role": config.evidence_role,
                "dataset_split": config.dataset_split,
                "protocol_version": config.protocol_version,
                "protocol_manifest_hash": (
                    config.protocol_manifest_hash
                ),
                "attack_estimate_eligible": (
                    config.attack_estimate_eligible
                ),
                "susceptibility_evidence": result.susceptibility_evidence,
                "capability_control_status": (
                    result.capability_control_status
                ),
                "attack_calibration_status": (
                    result.attack_calibration_status
                ),
                "complete_matched_sets": result.complete_matched_sets,
                "incomplete_matched_sets": result.incomplete_matched_sets,
                "complete_empirical_matched_sets": (
                    result.complete_empirical_matched_sets
                ),
                "shared_prelude_failures": result.shared_prelude_failures,
                "model_backend_accounting": dict(
                    result.model_backend_accounting
                ),
                "matched_attack_metrics": dict(
                    result.matched_attack_metrics
                ),
                "clean_noise_floor_metrics": dict(
                    result.clean_noise_floor_metrics
                ),
                "evidence_notice": (
                    result_experiment["evidence_notice"]
                ),
                "scheduled_runs": len(result.manifest),
                "completed_runs": len(result.manifest) - error_runs,
                "error_runs": error_runs,
                "aggregate_by_condition": result.aggregate_by_condition,
                "matched_comparisons": len(result.matched_comparisons),
                "external_side_effects": external_effects,
                "trace_path": str(args.trace.resolve()),
                "summary_path": str(summary_path.resolve()),
            }
        )
    )
    return 1 if error_runs else 0


def _git_provenance() -> tuple[str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return "unavailable", True
    return commit or "unavailable", bool(status.strip())


def _run_testbed(args: argparse.Namespace) -> int:
    tasks = load_tasks(args.tasks)
    if args.task_id is not None:
        tasks = [task for task in tasks if task.task_id == args.task_id]
        if not tasks:
            raise ValueError(f"Unknown task_id: {args.task_id}")

    position_channels = {
        "both": (
            IngressChannel.TOOL_OUTPUT.value,
            IngressChannel.DIRECT_USER_PROMPT.value,
        ),
        "tool-output": (IngressChannel.TOOL_OUTPUT.value,),
        "direct-user-prompt": (IngressChannel.DIRECT_USER_PROMPT.value,),
    }
    summary_path = args.summary or args.trace.with_suffix(".summary.json")
    code_commit, code_dirty = _git_provenance()
    config = PropagationConfig(
        experiment_id=args.experiment_id,
        repetitions=args.repetitions,
        seed=args.seed,
        policy_name=args.policy,
        guard_mode=GuardMode(args.guard).value,
        ingress_channels=position_channels[args.position],
        code_commit=code_commit,
        code_dirty=code_dirty,
    )
    result = run_propagation_testbed(
        tasks,
        config,
        trace_path=args.trace,
        summary_path=summary_path,
        overwrite=args.overwrite,
    )
    result_mapping = result.to_mapping()
    external_side_effects = sum(
        bool(summary.external_side_effect) for summary in result.summaries
    )
    print(
        canonical_json(
            {
                "mode": "scripted_propagation_diagnostic",
                "instrumentation_only": True,
                "evidence_scope": result_mapping["evidence_scope"],
                "attack_estimate_eligible": False,
                "empirical_llm_observation": False,
                "evidence_notice": result_mapping["evidence_notice"],
                "experiment_id": config.experiment_id,
                "policy": config.policy_name,
                "guard_mode": config.guard_mode,
                "ingress_channels": list(config.ingress_channels),
                "scheduled_runs": len(result.manifest),
                "completed_runs": len(result.summaries),
                "external_side_effects": external_side_effects,
                "aggregate": result.aggregate,
                "trace_path": str(args.trace.resolve()),
                "summary_path": str(summary_path.resolve()),
            }
        )
    )
    return 0


def _read_json_receipt(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Qualification receipt is not valid JSON: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(
            f"Qualification receipt must contain a JSON object: {path}"
        )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return _run(args)
        if args.command == "testbed":
            return _run_testbed(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return 1
    parser.error(f"Unsupported command: {args.command}")
    return 2
