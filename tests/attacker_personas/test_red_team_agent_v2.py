"""
Tests for RedTeamAgentWithPersona
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from agent_bounty.agents.red_team_agent_v2 import (
    RedTeamAgentWithPersona, AttackPhase, AttackStatus
)
from agent_bounty.attacker_personas.persona import (
    AttackerPersona, SophisticationLevel, StealthLevel, AttackSpeed
)


class TestRedTeamAgentWithPersona:
    """Test cases for RedTeamAgentWithPersona class."""

    @pytest.fixture
    def mock_persona(self):
        """Create a mock persona for testing."""
        persona = Mock(spec=AttackerPersona)
        persona.name = "Test APT"
        persona.mitre_id = "G0001"
        persona.sophistication_level = SophisticationLevel.HIGH
        persona.stealth_preference = StealthLevel.BALANCED
        persona.attack_speed = AttackSpeed.MODERATE
        persona.technique_success_rate = 0.8
        persona.persistence_priority = 0.7
        persona.data_exfiltration_priority = 0.6
        persona.tactics = ["initial-access", "persistence", "exfiltration"]
        persona.techniques = [
            {
                "external_id": "T1566.002",
                "name": "Spearphishing Link",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ]
            }
        ]
        persona.to_dict.return_value = {
            "name": "Test APT",
            "mitre_id": "G0001",
            "sophistication": "high"
        }
        persona.get_attack_chain.return_value = [
            {
                "tactic": "initial-access",
                "technique_id": "T1566.002",
                "technique_name": "Spearphishing Link",
                "description": "Send malicious links..."
            },
            {
                "tactic": "persistence",
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys",
                "description": "Modify registry..."
            }
        ]
        persona.should_use_stealth_technique.return_value = True
        persona.select_technique_for_tactic.return_value = {
            "external_id": "T1566.002",
            "name": "Spearphishing Link",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ]
        }
        return persona

    @pytest.fixture
    def mock_mitre_client(self):
        """Mock MITRE client."""
        client = Mock()
        client.get_technique_by_id.return_value = {
            "name": "Test Technique",
            "description": "A test technique",
            "kill_chain_phases": [
                {"phase_name": "initial-access"}
            ]
        }
        return client

    @pytest.fixture
    def mock_persona_library(self, mock_persona):
        """Mock persona library."""
        library = Mock()
        library.get_persona.return_value = mock_persona
        library.list_available_personas.return_value = ["APT29", "APT28", "Test APT"]
        return library

    @pytest.fixture
    def agent(self, mock_mitre_client, mock_persona_library):
        """Create RedTeamAgent with mocked dependencies."""
        with patch('agent_bounty.agents.red_team_agent_v2.MITREStixClient', return_value=mock_mitre_client):
            with patch('agent_bounty.agents.red_team_agent_v2.PersonaLibrary', return_value=mock_persona_library):
                return RedTeamAgentWithPersona()

    def test_initialization_without_persona(self, mock_mitre_client):
        """Test agent initialization without persona."""
        with patch('agent_bounty.agents.red_team_agent_v2.MITREStixClient', return_value=mock_mitre_client):
            agent = RedTeamAgentWithPersona()

            assert agent.persona is None
            assert agent.attack_history == []
            assert agent.current_campaign is None

    def test_initialization_with_persona(self, mock_mitre_client, mock_persona_library):
        """Test agent initialization with persona."""
        with patch('agent_bounty.agents.red_team_agent_v2.MITREStixClient', return_value=mock_mitre_client):
            with patch('agent_bounty.agents.red_team_agent_v2.PersonaLibrary', return_value=mock_persona_library):
                agent = RedTeamAgentWithPersona(persona_name="Test APT")

                assert agent.persona is not None
                assert agent.persona.name == "Test APT"

    def test_set_persona(self, agent, mock_persona_library, mock_persona):
        """Test setting persona."""
        agent.set_persona("Test APT")

        assert agent.persona == mock_persona
        mock_persona_library.get_persona.assert_called_with("Test APT")

    def test_list_available_personas(self, agent, mock_persona_library):
        """Test listing available personas."""
        personas = agent.list_available_personas()

        assert "Test APT" in personas
        mock_persona_library.list_available_personas.assert_called_once()

    def test_execute_attack_campaign_no_persona(self, agent):
        """Test attack execution without persona set."""
        with pytest.raises(ValueError, match="No persona set"):
            agent.execute_attack_campaign(target="test-target")

    def test_execute_attack_campaign_plan_only(self, agent, mock_persona):
        """Test attack campaign planning without execution."""
        agent.persona = mock_persona

        campaign = agent.execute_attack_campaign(
            target="192.168.1.0/24",
            scenario="full_chain",
            auto_execute=False
        )

        assert campaign['target'] == "192.168.1.0/24"
        assert campaign['status'] == 'completed'
        assert 'attack_plan' in campaign
        assert len(campaign['phases']) > 0

        # All phases should be planned, not executed
        for phase in campaign['phases']:
            assert phase['status'] == AttackStatus.PLANNED

    def test_execute_attack_campaign_with_execution(self, agent, mock_persona):
        """Test attack campaign with execution."""
        agent.persona = mock_persona

        # Mock random for predictable results
        with patch('random.random', return_value=0.5):  # 50% for success/detection
            campaign = agent.execute_attack_campaign(
                target="192.168.1.0/24",
                scenario="full_chain",
                auto_execute=True
            )

        assert campaign['target'] == "192.168.1.0/24"
        assert campaign['status'] == 'completed'
        assert 'success_rate' in campaign
        assert 'detection_rate' in campaign
        assert 'risk_score' in campaign

        # Should have executed phases
        executed_phases = [p for p in campaign['phases'] if p['status'] != AttackStatus.PLANNED]
        assert len(executed_phases) > 0

    def test_generate_persona_attack_plan(self, agent, mock_persona):
        """Test attack plan generation."""
        agent.persona = mock_persona

        plan = agent._generate_persona_attack_plan("full_chain")

        assert len(plan) > 0
        assert all('tactic' in phase for phase in plan)
        assert all('technique_id' in phase for phase in plan)
        assert all('technique_name' in phase for phase in plan)

    def test_execute_phase_success(self, agent, mock_persona, mock_mitre_client):
        """Test successful phase execution."""
        agent.persona = mock_persona
        agent.mitre_client = mock_mitre_client
        agent.current_campaign = {
            'detection_events': [],
            'techniques_used': [],
            'objectives_completed': [],
            'data_exfiltrated': 0
        }

        phase = {
            'tactic': 'initial-access',
            'technique_id': 'T1566.002',
            'technique_name': 'Spearphishing Link',
            'expected_delay_minutes': 0
        }

        # Mock high success probability
        with patch.object(agent, '_calculate_success_probability', return_value=0.9):
            with patch.object(agent, '_calculate_detection_probability', return_value=0.1):
                with patch('random.random', return_value=0.5):  # Success but not detected
                    result = agent._execute_phase(phase, "test-target")

        assert result['status'] == AttackStatus.SUCCESS
        assert result['detected'] == False
        assert result['tactic'] == 'initial-access'
        assert 'artifacts' in result
        assert 'indicators' in result

    def test_execute_phase_failure(self, agent, mock_persona, mock_mitre_client):
        """Test failed phase execution."""
        agent.persona = mock_persona
        agent.mitre_client = mock_mitre_client
        agent.current_campaign = {
            'detection_events': [],
            'techniques_used': [],
            'objectives_completed': [],
            'data_exfiltrated': 0
        }

        phase = {
            'tactic': 'initial-access',
            'technique_id': 'T1566.002',
            'technique_name': 'Spearphishing Link',
            'expected_delay_minutes': 0
        }

        # Mock low success probability
        with patch.object(agent, '_calculate_success_probability', return_value=0.1):
            with patch.object(agent, '_calculate_detection_probability', return_value=0.1):
                with patch('random.random', return_value=0.5):  # Failure
                    result = agent._execute_phase(phase, "test-target")

        assert result['status'] == AttackStatus.FAILED

    def test_execute_phase_blocked(self, agent, mock_persona, mock_mitre_client):
        """Test blocked phase execution."""
        agent.persona = mock_persona
        agent.mitre_client = mock_mitre_client
        agent.current_campaign = {
            'detection_events': [],
            'techniques_used': [],
            'objectives_completed': [],
            'data_exfiltrated': 0
        }

        phase = {
            'tactic': 'initial-access',
            'technique_id': 'T1566.002',
            'technique_name': 'Spearphishing Link',
            'expected_delay_minutes': 0
        }

        # Mock detection and blocking
        with patch.object(agent, '_calculate_success_probability', return_value=0.9):
            with patch.object(agent, '_calculate_detection_probability', return_value=0.9):
                with patch('random.random') as mock_random:
                    # First call: success, second: detected, third: blocked
                    mock_random.side_effect = [0.1, 0.1, 0.1]
                    result = agent._execute_phase(phase, "test-target")

        assert result['status'] == AttackStatus.BLOCKED
        assert result['detected'] == True

    def test_calculate_phase_delay(self, agent, mock_persona):
        """Test phase delay calculation."""
        agent.persona = mock_persona

        # Test different attack speeds
        mock_persona.attack_speed = AttackSpeed.SLOW
        delay = agent._calculate_phase_delay()
        assert delay >= 60  # At least 1 hour for slow

        mock_persona.attack_speed = AttackSpeed.FAST
        delay = agent._calculate_phase_delay()
        assert delay <= 15  # At most 15 minutes for fast

    def test_calculate_success_probability(self, agent, mock_persona):
        """Test success probability calculation."""
        agent.persona = mock_persona

        phase = {'tactic': 'initial-access'}

        # Test with different sophistication levels
        mock_persona.sophistication_level = SophisticationLevel.ADVANCED
        prob = agent._calculate_success_probability(phase)
        assert prob > 0.8  # Should be high for advanced

        mock_persona.sophistication_level = SophisticationLevel.LOW
        prob = agent._calculate_success_probability(phase)
        assert prob < 0.8  # Should be lower for low sophistication

    def test_calculate_detection_probability(self, agent, mock_persona):
        """Test detection probability calculation."""
        agent.persona = mock_persona

        phase = {'tactic': 'initial-access', 'stealth_mode': False}

        # Test with different stealth preferences
        mock_persona.stealth_preference = StealthLevel.STEALTHY
        prob = agent._calculate_detection_probability(phase)
        stealthy_prob = prob

        mock_persona.stealth_preference = StealthLevel.NOISY
        prob = agent._calculate_detection_probability(phase)
        noisy_prob = prob

        assert noisy_prob > stealthy_prob

    def test_get_tactic_priority(self, agent, mock_persona):
        """Test tactic priority calculation."""
        agent.persona = mock_persona

        # Test different tactics
        initial_access_priority = agent._get_tactic_priority('initial-access')
        impact_priority = agent._get_tactic_priority('impact')

        assert initial_access_priority > impact_priority

        # Test with high persistence priority
        mock_persona.persistence_priority = 0.9
        persistence_priority = agent._get_tactic_priority('persistence')
        assert persistence_priority >= 8

    def test_get_alternative_technique(self, agent, mock_persona):
        """Test alternative technique selection."""
        agent.persona = mock_persona

        original_phase = {
            'tactic': 'initial-access',
            'technique_id': 'T1566.002',
            'priority': 5
        }

        # Mock alternative technique
        mock_persona.select_technique_for_tactic.return_value = {
            'external_id': 'T1566.001',
            'name': 'Spearphishing Attachment'
        }

        alternative = agent._get_alternative_technique(original_phase)

        assert alternative is not None
        assert alternative['technique_id'] == 'T1566.001'
        assert alternative['stealth_mode'] == True  # Should use stealth for alternative

    def test_generate_attack_artifacts(self, agent):
        """Test attack artifact generation."""
        # Test different tactics
        initial_access_phase = {'tactic': 'initial-access'}
        artifacts = agent._generate_attack_artifacts(initial_access_phase)
        assert len(artifacts) > 0
        assert any(a['type'] == 'network' for a in artifacts)

        execution_phase = {'tactic': 'execution'}
        artifacts = agent._generate_attack_artifacts(execution_phase)
        assert any(a['type'] == 'process' for a in artifacts)

    def test_generate_indicators(self, agent):
        """Test IoC generation."""
        phase = {'technique_id': 'T1566.002'}
        indicators = agent._generate_indicators(phase)
        assert len(indicators) > 0

        # Test different technique types
        credential_phase = {'technique_id': 'T1003.001'}
        indicators = agent._generate_indicators(credential_phase)
        assert any('credential' in indicator.lower() for indicator in indicators)

    def test_get_mitigation_suggestions(self, agent, mock_mitre_client):
        """Test mitigation suggestion generation."""
        agent.mitre_client = mock_mitre_client

        mitigations = agent._get_mitigation_suggestions('T1566.002')
        assert len(mitigations) > 0
        assert len(mitigations) <= 3  # Should return top 3

    def test_calculate_campaign_metrics(self, agent, mock_persona):
        """Test campaign metrics calculation."""
        agent.persona = mock_persona
        agent.current_campaign = {
            'phases': [
                {'status': AttackStatus.SUCCESS, 'detected': False, 'tactic': 'initial-access'},
                {'status': AttackStatus.FAILED, 'detected': True, 'tactic': 'persistence'},
                {'status': AttackStatus.SUCCESS, 'detected': False, 'tactic': 'exfiltration'}
            ],
            'objectives_completed': ['initial_access', 'data_exfiltrated']
        }

        agent._calculate_campaign_metrics()

        assert 'success_rate' in agent.current_campaign
        assert 'detection_rate' in agent.current_campaign
        assert 'risk_score' in agent.current_campaign
        assert 'objectives_achieved' in agent.current_campaign

        # Check success rate calculation (2/3 = 0.67)
        assert abs(agent.current_campaign['success_rate'] - 0.67) < 0.01

        # Check detection rate (1/3 = 0.33)
        assert abs(agent.current_campaign['detection_rate'] - 0.33) < 0.01

    def test_generate_attack_report(self, agent, mock_persona):
        """Test attack report generation."""
        agent.persona = mock_persona
        agent.current_campaign = {
            'id': 'test-campaign',
            'persona': {'name': 'Test APT', 'mitre_id': 'G0001'},
            'target': 'test-target',
            'start_time': '2023-01-01T00:00:00',
            'end_time': '2023-01-01T01:00:00',
            'techniques_used': ['T1566.002'],
            'success_rate': 0.8,
            'detection_rate': 0.2,
            'risk_score': 75,
            'data_exfiltrated': 50,
            'objectives_achieved': {'initial_access': True, 'data_theft': True},
            'phases': []
        }

        report = agent.generate_attack_report()

        assert report['campaign_id'] == 'test-campaign'
        assert report['persona'] == 'Test APT'
        assert report['success_rate'] == '80.0%'
        assert report['detection_rate'] == '20.0%'
        assert report['risk_score'] == 75
        assert 'key_findings' in report
        assert 'recommendations' in report

    def test_calculate_duration(self, agent):
        """Test duration calculation."""
        campaign = {
            'start_time': '2023-01-01T00:00:00',
            'end_time': '2023-01-01T01:30:00'
        }

        duration = agent._calculate_duration(campaign)
        assert "1.5 hours" in duration

        # Test with missing timestamps
        incomplete_campaign = {'start_time': '2023-01-01T00:00:00'}
        duration = agent._calculate_duration(incomplete_campaign)
        assert duration == "Unknown"

    def test_generate_key_findings(self, agent):
        """Test key findings generation."""
        campaign = {
            'success_rate': 0.8,
            'detection_rate': 0.2,
            'objectives_achieved': {
                'persistence': True,
                'data_theft': True,
                'lateral_movement': True
            },
            'data_exfiltrated': 100
        }

        findings = agent._generate_key_findings(campaign)
        assert len(findings) > 0
        assert any('High success rate' in finding for finding in findings)
        assert any('persistence' in finding for finding in findings)

    def test_generate_recommendations(self, agent):
        """Test recommendations generation."""
        campaign = {
            'phases': [
                {
                    'status': AttackStatus.SUCCESS,
                    'detected': False,
                    'tactic': 'initial-access'
                },
                {
                    'status': AttackStatus.SUCCESS,
                    'detected': False,
                    'tactic': 'persistence'
                }
            ],
            'detection_rate': 0.1,
            'risk_score': 85
        }

        recommendations = agent._generate_recommendations(campaign)
        assert len(recommendations) > 0
        assert len(recommendations) <= 5  # Should limit to 5


if __name__ == "__main__":
    pytest.main([__file__])