"""New scenario profiles cannot silently alter an old frozen evaluation condition."""

import pytest
from agentdojo.task_suite.load_suites import get_suite
from test_evaluation_runner import config, spec
from test_heldout_runner import heldout_config, trial

from agentdojo_lab.evaluation_runner import InputComparisonTrial, validate_evaluation
from agentdojo_lab.heldout_runner import validate_heldout


@pytest.mark.parametrize("profile", ["implicit_string", "safe_control"])
def test_legacy_protocols_reject_new_profiles(profile):
    suite = get_suite("v1.2.2", "workspace")
    for assignment in (spec(), InputComparisonTrial(**spec().model_dump(), input_condition="canary")):
        with pytest.raises(ValueError, match="ordinary"):
            validate_evaluation(config(cascade_profile=profile), assignment, suite)
    with pytest.raises(ValueError, match="ordinary"):
        validate_heldout(heldout_config(cascade_profile=profile), trial(), suite)
    with pytest.raises(ValueError, match="ordinary"):
        validate_evaluation(heldout_config(cascade_profile=profile), trial(), suite)


def test_ordinary_profile_keeps_old_native_protocols_valid():
    suite = get_suite("v1.2.2", "workspace")
    validate_evaluation(config(), spec(), suite)
    validate_heldout(heldout_config(), trial(), suite)
