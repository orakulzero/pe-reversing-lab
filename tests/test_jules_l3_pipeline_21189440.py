import pytest
from pe_reversing_lab.l3_pipeline import StaticTriagePipeline, SAMPLE_PROFILES

def test_triage_sample_invalid_profile_with_whitespace():
    """
    Test the behavior of the `triage_sample` method when an invalid profile name
    containing leading/trailing whitespace is passed, ensuring it raises a `ValueError`
    with the correct list of allowed profiles.
    """
    pipeline = StaticTriagePipeline()
    invalid_profile = "  invalid_profile_name  "
    
    with pytest.raises(ValueError) as exc_info:
        pipeline.triage_sample(profile=invalid_profile)
        
    expected_allowed = list(SAMPLE_PROFILES.keys())
    expected_msg = f"Unknown sample profile '{invalid_profile}'. Allowed: {expected_allowed}"
    assert str(exc_info.value) == expected_msg
