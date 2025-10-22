"""
Tests for PersonaLibrary
"""

import pytest
from unittest.mock import Mock, patch

from agent_bounty.attacker_personas.persona_library import (
    PersonaLibrary, PERSONA_CONFIGS
)
from agent_bounty.attacker_personas.persona import (
    AttackerPersona, SophisticationLevel, StealthLevel
)


class TestPersonaLibrary:
    """Test cases for PersonaLibrary class."""

    @pytest.fixture
    def mock_mitre_client(self):
        """Mock MITRE client for testing."""
        client = Mock()
        client.get_group_by_name.return_value = {
            "id": "intrusion-set--test-123",
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes"],
            "description": "APT29 is a threat group...",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0016"}
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
                "name": "Cobalt Strike",
                "external_id": "S0154",
                "type": "tool"
            }
        ]
        client.get_all_groups.return_value = [
            {
                "name": "APT29",
                "mitre_id": "G0016",
                "aliases": ["Cozy Bear"]
            },
            {
                "name": "APT28",
                "mitre_id": "G0007",
                "aliases": ["Fancy Bear"]
            }
        ]
        return client

    @pytest.fixture
    def persona_library(self, mock_mitre_client):
        """Create PersonaLibrary with mocked client."""
        return PersonaLibrary(mitre_client=mock_mitre_client)

    def test_initialization(self, mock_mitre_client):
        """Test PersonaLibrary initialization."""
        library = PersonaLibrary(mitre_client=mock_mitre_client, cache_personas=True)
        assert library.mitre_client == mock_mitre_client
        assert library._personas_cache == {}

        # Test without caching
        library_no_cache = PersonaLibrary(mitre_client=mock_mitre_client, cache_personas=False)
        assert library_no_cache._personas_cache is None

    def test_get_persona_preconfigured(self, persona_library):
        """Test getting pre-configured persona."""
        persona = persona_library.get_persona("APT29")

        assert persona.name == "APT29"
        assert persona.mitre_id == "G0016"
        assert persona.sophistication_level == SophisticationLevel.ADVANCED
        assert persona.stealth_preference == StealthLevel.STEALTHY
        assert "Government" in persona.target_industries

    def test_get_persona_caching(self, persona_library):
        """Test persona caching functionality."""
        # First call
        persona1 = persona_library.get_persona("APT29")

        # Second call should return cached instance
        persona2 = persona_library.get_persona("APT29")

        assert persona1 is persona2  # Same object reference

    def test_get_persona_unknown(self, persona_library):
        """Test error handling for unknown persona."""
        with pytest.raises(ValueError, match="Unknown persona: 'UnknownAPT'"):
            persona_library.get_persona("UnknownAPT")

    def test_get_persona_from_mitre_only(self, persona_library):
        """Test creating persona from MITRE data without pre-config."""
        # Mock group that's not in PERSONA_CONFIGS
        persona_library.mitre_client.get_group_by_name.return_value = {
            "id": "intrusion-set--unknown",
            "name": "Unknown Group",
            "aliases": [],
            "description": "An unknown group",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G9999"}
            ]
        }

        persona = persona_library.get_persona("Unknown Group")
        assert persona.name == "Unknown Group"
        assert persona.mitre_id == "G9999"

    def test_get_persona_mitre_not_found(self, persona_library):
        """Test error when persona not found in MITRE data."""
        persona_library.mitre_client.get_group_by_name.return_value = None

        with pytest.raises(ValueError, match="Unknown persona: 'NonExistent'"):
            persona_library.get_persona("NonExistent")

    def test_list_available_personas(self, persona_library):
        """Test listing available personas."""
        personas = persona_library.list_available_personas()

        assert isinstance(personas, list)
        assert "APT29" in personas
        assert "APT28" in personas
        assert "Lazarus Group" in personas
        assert "FIN7" in personas

    def test_create_custom_persona_from_scratch(self, persona_library):
        """Test creating custom persona from scratch."""
        custom_persona = persona_library.create_custom_persona(
            name="Custom APT",
            sophistication_level=SophisticationLevel.HIGH,
            stealth_preference=StealthLevel.BALANCED,
            target_industries=["Finance"],
            motivations=["financial"],
            description="A custom threat actor"
        )

        assert custom_persona.name == "Custom APT"
        assert custom_persona.sophistication_level == SophisticationLevel.HIGH
        assert "Finance" in custom_persona.target_industries
        assert custom_persona.stix_id.startswith("custom--")
        assert custom_persona.mitre_id.startswith("C")

    def test_create_custom_persona_from_base(self, persona_library):
        """Test creating custom persona based on existing one."""
        # First get the base persona to populate cache
        base_persona = persona_library.get_persona("APT29")

        custom_persona = persona_library.create_custom_persona(
            name="APT29 Variant",
            base_persona="APT29",
            target_industries=["Healthcare"],
            description="Modified APT29 targeting healthcare"
        )

        assert custom_persona.name == "APT29 Variant"
        assert custom_persona.description == "Modified APT29 targeting healthcare"
        assert "Healthcare" in custom_persona.target_industries
        # Should inherit techniques from base
        assert len(custom_persona.techniques) > 0

    def test_list_all_mitre_groups(self, persona_library):
        """Test listing all MITRE groups."""
        groups = persona_library.list_all_mitre_groups()

        assert len(groups) == 2
        assert groups[0]["name"] == "APT29"
        assert groups[0]["mitre_id"] == "G0016"
        assert groups[1]["name"] == "APT28"

    def test_get_personas_by_industry(self, persona_library):
        """Test filtering personas by industry."""
        financial_personas = persona_library.get_personas_by_industry("Financial")

        assert "FIN7" in financial_personas
        assert "Lazarus Group" in financial_personas

        # Case insensitive test
        gov_personas = persona_library.get_personas_by_industry("government")
        assert "APT29" in gov_personas
        assert "APT28" in gov_personas

    def test_get_personas_by_sophistication(self, persona_library):
        """Test filtering personas by sophistication level."""
        advanced_personas = persona_library.get_personas_by_sophistication(
            SophisticationLevel.ADVANCED
        )

        assert "APT29" in advanced_personas
        assert "APT28" in advanced_personas
        assert "Lazarus Group" in advanced_personas

        high_personas = persona_library.get_personas_by_sophistication(
            SophisticationLevel.HIGH
        )
        assert "FIN7" in high_personas

    def test_get_personas_by_motivation(self, persona_library):
        """Test filtering personas by motivation."""
        espionage_personas = persona_library.get_personas_by_motivation("espionage")
        assert "APT29" in espionage_personas
        assert "APT28" in espionage_personas

        financial_personas = persona_library.get_personas_by_motivation("financial")
        assert "FIN7" in financial_personas
        assert "Lazarus Group" in financial_personas

    def test_compare_personas(self, persona_library):
        """Test persona comparison functionality."""
        # Mock different technique sets for comparison
        persona_library.mitre_client.get_techniques_for_group.side_effect = [
            # APT29 techniques
            [
                {"external_id": "T1566.002", "name": "Spearphishing Link"},
                {"external_id": "T1055", "name": "Process Injection"}
            ],
            # APT28 techniques
            [
                {"external_id": "T1566.002", "name": "Spearphishing Link"},
                {"external_id": "T1003", "name": "Credential Dumping"}
            ]
        ]

        comparison = persona_library.compare_personas("APT29", "APT28")

        assert comparison["persona1"]["name"] == "APT29"
        assert comparison["persona2"]["name"] == "APT28"
        assert comparison["common_techniques"] == 1  # T1566.002
        assert "unique_techniques" in comparison["persona1"]
        assert "unique_techniques" in comparison["persona2"]

    def test_clear_cache(self, persona_library):
        """Test cache clearing functionality."""
        # Load a persona to populate cache
        persona_library.get_persona("APT29")
        assert len(persona_library._personas_cache) > 0

        # Clear cache
        persona_library.clear_cache()
        assert len(persona_library._personas_cache) == 0

    def test_persona_configs_structure(self):
        """Test that PERSONA_CONFIGS has expected structure."""
        assert "APT29" in PERSONA_CONFIGS
        assert "APT28" in PERSONA_CONFIGS
        assert "Lazarus Group" in PERSONA_CONFIGS
        assert "FIN7" in PERSONA_CONFIGS

        # Test APT29 config structure
        apt29_config = PERSONA_CONFIGS["APT29"]
        assert "sophistication_level" in apt29_config
        assert "stealth_preference" in apt29_config
        assert "target_industries" in apt29_config
        assert "motivations" in apt29_config
        assert apt29_config["sophistication_level"] == SophisticationLevel.ADVANCED

    def test_persona_configs_completeness(self):
        """Test that all persona configs have required fields."""
        required_fields = [
            "sophistication_level",
            "stealth_preference",
            "target_industries",
            "motivations"
        ]

        for persona_name, config in PERSONA_CONFIGS.items():
            for field in required_fields:
                assert field in config, f"Missing {field} in {persona_name} config"

    def test_custom_persona_tracking(self, persona_library):
        """Test that custom personas are tracked separately."""
        # Create custom persona
        custom1 = persona_library.create_custom_persona(
            name="Custom 1",
            description="First custom persona"
        )

        # Create another
        custom2 = persona_library.create_custom_persona(
            name="Custom 2",
            description="Second custom persona"
        )

        # Check they're tracked
        assert "Custom 1" in persona_library._custom_personas
        assert "Custom 2" in persona_library._custom_personas

        # Check they can be retrieved
        retrieved = persona_library.get_persona("Custom 1")
        assert retrieved.name == "Custom 1"
        assert retrieved is custom1

    def test_no_caching_mode(self, mock_mitre_client):
        """Test library with caching disabled."""
        library = PersonaLibrary(mitre_client=mock_mitre_client, cache_personas=False)

        # Get persona twice
        persona1 = library.get_persona("APT29")
        persona2 = library.get_persona("APT29")

        # Should create new instances each time
        assert persona1 is not persona2
        assert persona1.name == persona2.name

    def test_error_handling_mitre_client_none(self):
        """Test error handling when MITRE client returns None."""
        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient') as mock_client_class:
            mock_client = Mock()
            mock_client.get_group_by_name.return_value = None
            mock_client_class.return_value = mock_client

            library = PersonaLibrary()

            with pytest.raises(ValueError):
                library.get_persona("NonExistent")


if __name__ == "__main__":
    pytest.main([__file__])