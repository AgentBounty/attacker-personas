"""
Tests for MITRE STIX Client
"""

import json
import pytest
from unittest.mock import Mock, patch, mock_open
from pathlib import Path
from datetime import datetime, timedelta

from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient


# Sample STIX data for testing
SAMPLE_STIX_DATA = {
    "type": "bundle",
    "objects": [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "name": "APT29",
            "aliases": ["YTTRIUM", "The Dukes", "Cozy Bear"],
            "description": "APT29 is a threat group...",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0016"}
            ]
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
            "name": "Spearphishing Link",
            "description": "Adversaries may send spearphishing emails...",
            "x_mitre_platforms": ["Windows", "macOS", "Linux"],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.002"}
            ]
        },
        {
            "type": "malware",
            "id": "malware--b42378e0-f147-496f-992a-26a49705395b",
            "name": "Cobalt Strike",
            "description": "Cobalt Strike is a commercial...",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0154"}
            ]
        },
        {
            "type": "relationship",
            "id": "relationship--12345",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "target_ref": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7"
        },
        {
            "type": "relationship",
            "id": "relationship--67890",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "target_ref": "malware--b42378e0-f147-496f-992a-26a49705395b"
        }
    ]
}


class TestMITREStixClient:
    """Test cases for MITREStixClient."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        return str(tmp_path / "test_cache")

    @pytest.fixture
    def mock_stix_data(self):
        """Mock STIX data for testing."""
        return SAMPLE_STIX_DATA

    @pytest.fixture
    def client_with_data(self, temp_cache_dir, mock_stix_data):
        """Create client with mocked data."""
        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._load_or_download'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)
            client.stix_data = mock_stix_data
            client._parse_stix_data()
            return client

    def test_init_creates_cache_directory(self, temp_cache_dir):
        """Test that initialization creates cache directory."""
        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._load_or_download'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)
            assert Path(temp_cache_dir).exists()

    @patch('requests.get')
    def test_download_latest_success(self, mock_get, temp_cache_dir):
        """Test successful download of STIX data."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '1000'}
        mock_response.iter_content.return_value = [b'{"test": "data"}']
        mock_get.return_value = mock_response

        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)
            client.download_latest()

        # Check that file was created
        assert (Path(temp_cache_dir) / "enterprise-attack.json").exists()
        assert (Path(temp_cache_dir) / "metadata.json").exists()

    @patch('requests.get')
    def test_download_latest_failure(self, mock_get, temp_cache_dir):
        """Test download failure handling."""
        mock_get.side_effect = Exception("Network error")

        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)

            with pytest.raises(RuntimeError, match="Failed to download STIX data"):
                client.download_latest()

    def test_cache_age_check_recent(self, temp_cache_dir):
        """Test cache age check with recent data."""
        # Create recent metadata
        metadata = {
            'download_time': datetime.now().isoformat(),
            'source_url': 'test',
            'file_size': 1000
        }

        metadata_file = Path(temp_cache_dir) / "metadata.json"
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)

        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)
            assert not client._is_cache_outdated()

    def test_cache_age_check_old(self, temp_cache_dir):
        """Test cache age check with old data."""
        # Create old metadata
        old_time = datetime.now() - timedelta(days=10)
        metadata = {
            'download_time': old_time.isoformat(),
            'source_url': 'test',
            'file_size': 1000
        }

        metadata_file = Path(temp_cache_dir) / "metadata.json"
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)

        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)
            assert client._is_cache_outdated()

    def test_get_group_by_name_exact_match(self, client_with_data):
        """Test finding group by exact name."""
        group = client_with_data.get_group_by_name("APT29")

        assert group is not None
        assert group['name'] == "APT29"
        assert group['id'] == "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"

    def test_get_group_by_name_alias_match(self, client_with_data):
        """Test finding group by alias."""
        group = client_with_data.get_group_by_name("Cozy Bear")

        assert group is not None
        assert group['name'] == "APT29"
        assert "Cozy Bear" in group['aliases']

    def test_get_group_by_name_case_insensitive(self, client_with_data):
        """Test case-insensitive group search."""
        group = client_with_data.get_group_by_name("apt29")
        assert group is not None
        assert group['name'] == "APT29"

    def test_get_group_by_name_not_found(self, client_with_data):
        """Test behavior when group is not found."""
        group = client_with_data.get_group_by_name("NonExistentGroup")
        assert group is None

    def test_get_techniques_for_group(self, client_with_data):
        """Test retrieving techniques for a group."""
        group_id = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
        techniques = client_with_data.get_techniques_for_group(group_id)

        assert len(techniques) == 1
        assert techniques[0]['name'] == "Spearphishing Link"
        assert techniques[0]['external_id'] == "T1566.002"

    def test_get_software_for_group(self, client_with_data):
        """Test retrieving software for a group."""
        group_id = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
        software = client_with_data.get_software_for_group(group_id)

        assert len(software) == 1
        assert software[0]['name'] == "Cobalt Strike"
        assert software[0]['external_id'] == "S0154"

    def test_get_technique_by_id(self, client_with_data):
        """Test retrieving technique by MITRE ID."""
        technique = client_with_data.get_technique_by_id("T1566.002")

        assert technique is not None
        assert technique['name'] == "Spearphishing Link"
        assert technique['external_id'] == "T1566.002"

    def test_get_technique_by_id_not_found(self, client_with_data):
        """Test behavior when technique is not found."""
        technique = client_with_data.get_technique_by_id("T9999")
        assert technique is None

    def test_get_all_groups(self, client_with_data):
        """Test retrieving all groups."""
        groups = client_with_data.get_all_groups()

        assert len(groups) == 1
        assert groups[0]['name'] == "APT29"
        assert groups[0]['mitre_id'] == "G0016"

    def test_get_tactics(self, client_with_data):
        """Test retrieving all tactics."""
        tactics = client_with_data.get_tactics()

        assert "initial-access" in tactics
        assert isinstance(tactics, list)

    def test_parse_stix_data_indexing(self, client_with_data):
        """Test that STIX data is properly indexed."""
        # Check objects by type
        assert 'intrusion-set' in client_with_data._objects_by_type
        assert 'attack-pattern' in client_with_data._objects_by_type
        assert 'malware' in client_with_data._objects_by_type

        # Check objects by ID
        group_id = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
        assert group_id in client_with_data._objects_by_id

        # Check relationships
        assert len(client_with_data._relationships) == 2

    @patch('builtins.open', mock_open(read_data='{"invalid": "json"'))
    def test_load_from_cache_invalid_json(self, temp_cache_dir):
        """Test handling of invalid JSON in cache."""
        with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
            client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)

            with pytest.raises(RuntimeError):
                client._load_from_cache()

    def test_refresh_cache(self, client_with_data):
        """Test cache refresh functionality."""
        with patch.object(client_with_data, 'download_latest') as mock_download:
            with patch.object(client_with_data, '_parse_stix_data') as mock_parse:
                client_with_data.refresh_cache()

                mock_download.assert_called_once()
                mock_parse.assert_called_once()

    def test_error_handling_network_issues(self, temp_cache_dir):
        """Test error handling for network issues."""
        with patch('requests.get', side_effect=Exception("Connection timeout")):
            with patch('agent_bounty.threat_intelligence.mitre_stix_client.MITREStixClient._parse_stix_data'):
                client = MITREStixClient(cache_dir=temp_cache_dir, auto_update=False)

                with pytest.raises(RuntimeError):
                    client.download_latest()


@pytest.mark.integration
class TestMITREStixClientIntegration:
    """Integration tests that hit the real MITRE API (optional)."""

    @pytest.mark.skip(reason="Requires network access")
    def test_real_download(self, tmp_path):
        """Test downloading real MITRE data."""
        cache_dir = str(tmp_path / "real_cache")
        client = MITREStixClient(cache_dir=cache_dir)

        # Should have downloaded and parsed data
        assert len(client._objects_by_type) > 0
        assert 'intrusion-set' in client._objects_by_type
        assert 'attack-pattern' in client._objects_by_type

    @pytest.mark.skip(reason="Requires network access")
    def test_real_apt29_lookup(self, tmp_path):
        """Test looking up real APT29 data."""
        cache_dir = str(tmp_path / "real_cache")
        client = MITREStixClient(cache_dir=cache_dir)

        group = client.get_group_by_name("APT29")
        assert group is not None
        assert "Cozy Bear" in group.get('aliases', [])

        techniques = client.get_techniques_for_group(group['id'])
        assert len(techniques) > 0


if __name__ == "__main__":
    pytest.main([__file__])