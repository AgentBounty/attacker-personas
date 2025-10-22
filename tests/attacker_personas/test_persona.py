"""
Tests for AttackerPersona core classes
"""

import pytest
from unittest.mock import Mock, patch

from agent_bounty.attacker_personas.persona import (
    AttackerPersona, SophisticationLevel, StealthLevel, AttackSpeed
)


class TestAttackerPersona:
    """Test cases for AttackerPersona class."""

    @pytest.fixture
    def sample_persona(self):
        """Create a sample persona for testing."""
        return AttackerPersona(
            stix_id="intrusion-set--test-123",
            mitre_id="G0001",
            name="Test APT",
            aliases=["Test Group", "APT Test"],
            description="A test threat group",
            tactics=["initial-access", "persistence", "exfiltration"],
            techniques=[
                {
                    "id": "attack-pattern--123",
                    "name": "Spearphishing Link",
                    "external_id": "T1566.002",
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ],
                    "description": "Adversaries may send spearphishing emails..."
                },
                {
                    "id": "attack-pattern--456",
                    "name": "Registry Run Keys",
                    "external_id": "T1547.001",
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}
                    ],
                    "description": "Adversaries may achieve persistence..."
                }
            ],
            software=[
                {
                    "id": "malware--test",
                    "name": "Test Malware",
                    "external_id": "S0001",
                    "type": "malware"
                }
            ],
            sophistication_level=SophisticationLevel.HIGH,
            stealth_preference=StealthLevel.STEALTHY,
            attack_speed=AttackSpeed.MODERATE,
            target_industries=["Technology", "Government"],
            target_regions=["North America"],
            motivations=["espionage"]
        )

    @pytest.fixture
    def mock_mitre_client(self):
        """Mock MITRE client for testing."""
        client = Mock()
        client.get_group_by_name.return_value = {
            "id": "intrusion-set--test-123",
            "name": "Test APT",
            "aliases": ["Test Group"],
            "description": "A test threat group",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0001"}
            ]
        }
        client.get_techniques_for_group.return_value = [
            {
                "id": "attack-pattern--123",
                "name": "Spearphishing Link",
                "external_id": "T1566.002",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ]
            }
        ]
        client.get_software_for_group.return_value = [
            {
                "id": "malware--test",
                "name": "Test Malware",
                "external_id": "S0001",
                "type": "malware"
            }
        ]
        return client

    def test_persona_initialization(self, sample_persona):
        """Test basic persona initialization."""
        assert sample_persona.name == "Test APT"
        assert sample_persona.mitre_id == "G0001"
        assert sample_persona.sophistication_level == SophisticationLevel.HIGH
        assert sample_persona.stealth_preference == StealthLevel.STEALTHY
        assert len(sample_persona.techniques) == 2
        assert len(sample_persona.software) == 1

    def test_from_mitre_data(self, mock_mitre_client):
        """Test creating persona from MITRE data."""
        persona = AttackerPersona.from_mitre_data(
            mock_mitre_client,
            "Test APT",
            sophistication_level=SophisticationLevel.ADVANCED
        )

        assert persona.name == "Test APT"
        assert persona.mitre_id == "G0001"
        assert persona.sophistication_level == SophisticationLevel.ADVANCED
        assert "initial-access" in persona.tactics

    def test_from_mitre_data_group_not_found(self, mock_mitre_client):
        """Test error handling when group is not found."""
        mock_mitre_client.get_group_by_name.return_value = None

        with pytest.raises(ValueError, match="Group 'NonExistent' not found"):
            AttackerPersona.from_mitre_data(mock_mitre_client, "NonExistent")

    def test_select_technique_for_tactic(self, sample_persona):
        """Test selecting technique for a specific tactic."""
        technique = sample_persona.select_technique_for_tactic("initial-access")

        assert technique is not None
        assert technique["name"] == "Spearphishing Link"
        assert technique["external_id"] == "T1566.002"

    def test_select_technique_for_tactic_not_found(self, sample_persona):
        """Test selecting technique for tactic not in persona's arsenal."""
        technique = sample_persona.select_technique_for_tactic("impact")
        assert technique is None

    def test_select_technique_with_exclusions(self, sample_persona):
        """Test selecting technique with exclusions."""
        # First call should return T1566.002
        technique1 = sample_persona.select_technique_for_tactic("initial-access")
        assert technique1["external_id"] == "T1566.002"

        # Call with exclusion should return None (no other initial-access techniques)
        technique2 = sample_persona.select_technique_for_tactic(
            "initial-access",
            exclude=["T1566.002"]
        )
        assert technique2 is None

    def test_get_attack_chain_full(self, sample_persona):
        """Test generating full attack chain."""
        chain = sample_persona.get_attack_chain("full_chain")

        assert len(chain) > 0
        # Should include available tactics
        tactic_names = [phase["tactic"] for phase in chain]
        assert "initial-access" in tactic_names
        assert "persistence" in tactic_names

    def test_get_attack_chain_ransomware(self, sample_persona):
        """Test generating ransomware attack chain."""
        chain = sample_persona.get_attack_chain("ransomware")

        # Should focus on specific tactics for ransomware
        tactic_names = [phase["tactic"] for phase in chain]
        expected_tactics = ["initial-access", "persistence"]
        for tactic in expected_tactics:
            if tactic in sample_persona.tactics:
                assert tactic in tactic_names

    def test_get_attack_chain_data_theft(self, sample_persona):
        """Test generating data theft attack chain."""
        chain = sample_persona.get_attack_chain("data_theft")

        # Should include exfiltration if available
        tactic_names = [phase["tactic"] for phase in chain]
        if "exfiltration" in sample_persona.tactics:
            assert "exfiltration" in tactic_names

    def test_should_use_stealth_technique(self, sample_persona):
        """Test stealth technique decision logic."""
        # STEALTHY persona should often use stealth
        stealth_count = sum(
            1 for _ in range(100)
            if sample_persona.should_use_stealth_technique()
        )
        assert stealth_count > 80  # Should be >90% but allowing for randomness

        # Change to NOISY and test
        sample_persona.stealth_preference = StealthLevel.NOISY
        noisy_count = sum(
            1 for _ in range(100)
            if sample_persona.should_use_stealth_technique()
        )
        assert noisy_count < 20  # Should be <10% but allowing for randomness

    def test_get_dwell_time(self, sample_persona):
        """Test dwell time calculation."""
        # HIGH sophistication should have longer dwell time
        dwell_time = sample_persona.get_dwell_time()
        assert dwell_time >= 180  # At least 6 months for HIGH

        # Test with different sophistication levels
        sample_persona.sophistication_level = SophisticationLevel.LOW
        low_dwell = sample_persona.get_dwell_time()
        assert low_dwell < dwell_time  # Should be shorter

        # Test stealth impact
        sample_persona.stealth_preference = StealthLevel.STEALTHY
        stealthy_dwell = sample_persona.get_dwell_time()

        sample_persona.stealth_preference = StealthLevel.NOISY
        noisy_dwell = sample_persona.get_dwell_time()
        assert stealthy_dwell > noisy_dwell

    def test_to_dict(self, sample_persona):
        """Test serialization to dictionary."""
        data = sample_persona.to_dict()

        assert data["name"] == "Test APT"
        assert data["mitre_id"] == "G0001"
        assert data["sophistication"] == "high"
        assert data["stealth"] == "stealthy"
        assert data["technique_count"] == 2
        assert data["software_count"] == 1
        assert "Technology" in data["target_industries"]

    def test_to_json_summary(self, sample_persona):
        """Test JSON summary generation."""
        summary = sample_persona.to_json_summary()

        assert summary["name"] == "Test APT"
        assert summary["mitre_id"] == "G0001"
        assert summary["sophistication"] == "high"
        assert summary["techniques"] == 2
        assert summary["tools"] == 1
        assert "initial-access" in summary["tactics"]

    def test_repr(self, sample_persona):
        """Test string representation."""
        repr_str = repr(sample_persona)
        assert "Test APT" in repr_str
        assert "G0001" in repr_str
        assert "high" in repr_str

    def test_categorize_techniques_by_tactic(self):
        """Test technique categorization by tactic."""
        techniques = [
            {
                "name": "Technique 1",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ]
            },
            {
                "name": "Technique 2",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}
                ]
            },
            {
                "name": "Technique 3",
                "kill_chain_phases": [
                    {"kill_chain_name": "other", "phase_name": "something"}
                ]
            }
        ]

        categorized = AttackerPersona._categorize_techniques_by_tactic(techniques)

        assert "initial-access" in categorized
        assert "persistence" in categorized
        assert "privilege-escalation" in categorized
        assert "something" not in categorized  # Different kill chain

        assert len(categorized["initial-access"]) == 1
        assert len(categorized["persistence"]) == 1
        assert len(categorized["privilege-escalation"]) == 1

    def test_set_preferred_techniques(self, sample_persona):
        """Test setting preferred techniques for tactics."""
        techniques_by_tactic = {
            "initial-access": [
                {"external_id": "T1566.001", "name": "Spearphishing Attachment"},
                {"external_id": "T1566.002", "name": "Spearphishing Link"}
            ],
            "persistence": [
                {"external_id": "T1547.001", "name": "Registry Run Keys"}
            ]
        }

        sample_persona._set_preferred_techniques(techniques_by_tactic)

        assert "T1566.001" in sample_persona.preferred_initial_access
        assert "T1566.002" in sample_persona.preferred_initial_access
        assert "T1547.001" in sample_persona.preferred_persistence

    def test_enum_values(self):
        """Test enum value assignments."""
        # Test SophisticationLevel
        assert SophisticationLevel.LOW.value == "low"
        assert SophisticationLevel.MEDIUM.value == "medium"
        assert SophisticationLevel.HIGH.value == "high"
        assert SophisticationLevel.ADVANCED.value == "advanced"

        # Test StealthLevel
        assert StealthLevel.NOISY.value == "noisy"
        assert StealthLevel.BALANCED.value == "balanced"
        assert StealthLevel.STEALTHY.value == "stealthy"

        # Test AttackSpeed
        assert AttackSpeed.SLOW.value == "slow"
        assert AttackSpeed.MODERATE.value == "moderate"
        assert AttackSpeed.FAST.value == "fast"
        assert AttackSpeed.AGGRESSIVE.value == "aggressive"

    def test_default_values(self):
        """Test default persona values."""
        minimal_persona = AttackerPersona(
            stix_id="test",
            mitre_id="G0000",
            name="Minimal Test"
        )

        assert minimal_persona.sophistication_level == SophisticationLevel.MEDIUM
        assert minimal_persona.stealth_preference == StealthLevel.BALANCED
        assert minimal_persona.attack_speed == AttackSpeed.MODERATE
        assert minimal_persona.aliases == []
        assert minimal_persona.tactics == []
        assert minimal_persona.techniques == []
        assert minimal_persona.software == []
        assert minimal_persona.max_techniques_per_phase == 3
        assert minimal_persona.technique_success_rate == 0.7


if __name__ == "__main__":
    pytest.main([__file__])