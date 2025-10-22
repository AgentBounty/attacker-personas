"""
Persona Integration Adapter
Connects attacker personas with existing Red Team agents
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Protocol
from dataclasses import dataclass
from enum import Enum

from agent_bounty.attacker_personas.persona import AttackerPersona
from agent_bounty.attacker_personas.persona_library import PersonaLibrary
from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient

logger = logging.getLogger(__name__)


class AgentType(str, Enum):
    """Types of agents that can be enhanced with personas."""
    RED_TEAM = "red_team"
    PENETRATION_TEST = "penetration_test"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    ATTACK_SIMULATOR = "attack_simulator"
    THREAT_EMULATOR = "threat_emulator"


@dataclass
class PersonaConfiguration:
    """Configuration for injecting persona into existing agents."""
    persona_name: str
    behavior_override: Optional[Dict[str, Any]] = None
    technique_filter: Optional[List[str]] = None  # Filter to specific techniques
    target_environment: Optional[str] = None
    campaign_objectives: Optional[List[str]] = None
    stealth_mode: Optional[bool] = None


class LegacyAgentInterface(Protocol):
    """Protocol defining interface for existing Red Team agents."""

    def execute_attack(self, target: str, techniques: List[str]) -> Dict[str, Any]:
        """Execute attack with specified techniques."""
        ...

    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set agent configuration."""
        ...

    def get_available_techniques(self) -> List[str]:
        """Get list of available techniques."""
        ...


class PersonaInjectableAgent(ABC):
    """Base class for agents that can be enhanced with personas."""

    @abstractmethod
    def inject_persona(self, persona: AttackerPersona) -> None:
        """Inject persona characteristics into the agent."""
        pass

    @abstractmethod
    def execute_persona_driven_attack(self, target: str, scenario: str = "full_chain") -> Dict[str, Any]:
        """Execute attack following persona's behavioral patterns."""
        pass


class PersonaAdapter:
    """
    Adapter that connects attacker personas with existing Red Team agents.

    Provides multiple integration patterns:
    1. Configuration injection - Modify existing agent configs
    2. Technique filtering - Filter available techniques by persona
    3. Behavioral wrapping - Wrap existing agents with persona behavior
    4. Campaign orchestration - Coordinate multi-agent persona campaigns
    """

    def __init__(self, persona_library: Optional[PersonaLibrary] = None):
        self.persona_library = persona_library or PersonaLibrary(auto_generate=True)
        self._registered_agents = {}

    def register_agent(self, agent_id: str, agent: Any, agent_type: AgentType) -> None:
        """Register an existing agent for persona integration."""
        self._registered_agents[agent_id] = {
            'agent': agent,
            'type': agent_type,
            'persona': None,
            'original_config': self._extract_agent_config(agent)
        }
        logger.info(f"Registered {agent_type.value} agent: {agent_id}")

    def inject_persona_into_agent(self, agent_id: str, persona_config: PersonaConfiguration) -> Dict[str, Any]:
        """
        Inject persona characteristics into an existing agent.

        Args:
            agent_id: ID of registered agent
            persona_config: Persona configuration to inject

        Returns:
            Updated agent configuration
        """
        if agent_id not in self._registered_agents:
            raise ValueError(f"Agent {agent_id} not registered")

        agent_info = self._registered_agents[agent_id]
        agent = agent_info['agent']

        # Load persona
        persona = self.persona_library.get_persona(persona_config.persona_name)
        agent_info['persona'] = persona

        # Create persona-driven configuration
        persona_driven_config = self._create_persona_config(persona, persona_config, agent_info['type'])

        # Apply configuration to agent
        self._apply_config_to_agent(agent, persona_driven_config)

        logger.info(f"Injected {persona.name} persona into agent {agent_id}")
        return persona_driven_config

    def create_persona_wrapper(self, existing_agent: Any, persona_name: str, agent_type: AgentType) -> 'PersonaWrappedAgent':
        """
        Create a wrapper around existing agent that adds persona behavior.

        Args:
            existing_agent: Existing agent to wrap
            persona_name: Name of persona to apply
            agent_type: Type of the existing agent

        Returns:
            Wrapped agent with persona behavior
        """
        persona = self.persona_library.get_persona(persona_name)
        return PersonaWrappedAgent(existing_agent, persona, agent_type, self)

    def orchestrate_multi_agent_campaign(self, campaign_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate a campaign using multiple agents with different personas.

        Args:
            campaign_config: Configuration for multi-agent campaign

        Returns:
            Campaign execution results
        """
        campaign_id = campaign_config.get('campaign_id', f"campaign_{len(self._registered_agents)}")
        target = campaign_config.get('target')
        agent_assignments = campaign_config.get('agent_assignments', [])

        results = {
            'campaign_id': campaign_id,
            'target': target,
            'agent_results': [],
            'coordination_log': []
        }

        for assignment in agent_assignments:
            agent_id = assignment['agent_id']
            persona_name = assignment['persona_name']
            objectives = assignment.get('objectives', [])

            # Configure agent with persona
            persona_config = PersonaConfiguration(
                persona_name=persona_name,
                campaign_objectives=objectives,
                target_environment=target
            )

            agent_config = self.inject_persona_into_agent(agent_id, persona_config)

            # Execute agent's part of campaign
            agent_info = self._registered_agents[agent_id]
            agent_result = self._execute_agent_with_persona(agent_info, assignment)

            results['agent_results'].append({
                'agent_id': agent_id,
                'persona_name': persona_name,
                'result': agent_result
            })

            results['coordination_log'].append(f"Executed {persona_name} via {agent_id}")

        return results

    def get_persona_recommendations(self, agent_type: AgentType, target_info: Dict[str, Any]) -> List[str]:
        """
        Recommend personas based on agent type and target characteristics.

        Args:
            agent_type: Type of agent
            target_info: Information about the target environment

        Returns:
            List of recommended persona names
        """
        target_industry = target_info.get('industry', '')
        target_region = target_info.get('region', '')
        attack_objectives = target_info.get('objectives', [])

        recommendations = []

        # Get all available personas
        available_personas = self.persona_library.list_available_personas()

        for persona_name in available_personas:
            try:
                persona = self.persona_library.get_persona(persona_name)
                score = self._calculate_persona_match_score(persona, target_info, agent_type)

                if score > 0.5:  # Threshold for recommendation
                    recommendations.append((persona_name, score))

            except Exception as e:
                logger.warning(f"Could not evaluate persona {persona_name}: {e}")
                continue

        # Sort by score and return top recommendations
        recommendations.sort(key=lambda x: x[1], reverse=True)
        return [name for name, score in recommendations[:10]]

    def migrate_legacy_agent(self, legacy_agent: Any, agent_type: AgentType) -> 'ModernPersonaAgent':
        """
        Migrate a legacy agent to use the new persona system.

        Args:
            legacy_agent: Existing legacy agent
            agent_type: Type of the legacy agent

        Returns:
            Modernized agent with persona capabilities
        """
        return ModernPersonaAgent(legacy_agent, agent_type, self.persona_library)

    def _extract_agent_config(self, agent: Any) -> Dict[str, Any]:
        """Extract current configuration from an agent."""
        config = {}

        # Try common configuration attributes
        for attr in ['config', 'configuration', 'settings', 'options']:
            if hasattr(agent, attr):
                config[attr] = getattr(agent, attr)

        # Try common method names
        for method in ['get_config', 'get_configuration', 'get_settings']:
            if hasattr(agent, method):
                try:
                    config[method] = getattr(agent, method)()
                except Exception:
                    pass

        return config

    def _create_persona_config(self, persona: AttackerPersona, persona_config: PersonaConfiguration, agent_type: AgentType) -> Dict[str, Any]:
        """Create configuration based on persona characteristics."""
        config = {
            'persona_name': persona.name,
            'mitre_id': persona.mitre_id,
            'sophistication_level': persona.sophistication_level.value,
            'stealth_preference': persona.stealth_preference.value,
            'attack_speed': persona.attack_speed.value,
            'target_industries': persona.target_industries,
            'target_regions': persona.target_regions,
            'motivations': persona.motivations,
            'preferred_techniques': [t.get('external_id', '') for t in persona.techniques[:20]],  # Top 20
            'preferred_tools': persona.preferred_tools,
            'detection_sensitivity': persona.detection_sensitivity,
            'persistence_priority': persona.persistence_priority,
            'data_exfiltration_priority': persona.data_exfiltration_priority
        }

        # Apply behavior overrides
        if persona_config.behavior_override:
            config.update(persona_config.behavior_override)

        # Apply technique filtering
        if persona_config.technique_filter:
            config['allowed_techniques'] = persona_config.technique_filter

        # Apply stealth mode override
        if persona_config.stealth_mode is not None:
            config['force_stealth_mode'] = persona_config.stealth_mode

        return config

    def _apply_config_to_agent(self, agent: Any, config: Dict[str, Any]) -> None:
        """Apply persona configuration to an agent."""
        # Try common configuration methods
        if hasattr(agent, 'set_configuration'):
            agent.set_configuration(config)
        elif hasattr(agent, 'configure'):
            agent.configure(config)
        elif hasattr(agent, 'set_config'):
            agent.set_config(config)
        elif hasattr(agent, 'update_config'):
            agent.update_config(config)
        else:
            # Try setting config attributes directly
            for key, value in config.items():
                if hasattr(agent, key):
                    setattr(agent, key, value)

    def _execute_agent_with_persona(self, agent_info: Dict[str, Any], assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an agent with persona-driven behavior."""
        agent = agent_info['agent']
        persona = agent_info['persona']

        # Try different execution methods
        if hasattr(agent, 'execute_attack'):
            return agent.execute_attack(
                target=assignment.get('target'),
                techniques=assignment.get('techniques', [])
            )
        elif hasattr(agent, 'run'):
            return agent.run(assignment)
        elif hasattr(agent, 'execute'):
            return agent.execute(assignment)
        else:
            logger.warning(f"No known execution method for agent {agent}")
            return {'status': 'error', 'message': 'No execution method found'}

    def _calculate_persona_match_score(self, persona: AttackerPersona, target_info: Dict[str, Any], agent_type: AgentType) -> float:
        """Calculate how well a persona matches target and agent type."""
        score = 0.0

        # Industry match
        target_industry = target_info.get('industry', '').lower()
        if target_industry:
            for industry in persona.target_industries:
                if target_industry in industry.lower():
                    score += 0.3
                    break

        # Region match
        target_region = target_info.get('region', '').lower()
        if target_region:
            for region in persona.target_regions:
                if target_region in region.lower():
                    score += 0.2
                    break

        # Objectives match
        objectives = target_info.get('objectives', [])
        for objective in objectives:
            if objective.lower() in [m.lower() for m in persona.motivations]:
                score += 0.2

        # Agent type compatibility
        if agent_type == AgentType.RED_TEAM:
            score += 0.2  # All personas work well with red team
        elif agent_type == AgentType.PENETRATION_TEST:
            if persona.sophistication_level.value in ['high', 'advanced']:
                score += 0.1

        return min(score, 1.0)


class PersonaWrappedAgent:
    """
    Wrapper that adds persona behavior to existing agents.
    """

    def __init__(self, wrapped_agent: Any, persona: AttackerPersona, agent_type: AgentType, adapter: PersonaAdapter):
        self.wrapped_agent = wrapped_agent
        self.persona = persona
        self.agent_type = agent_type
        self.adapter = adapter

        # Apply persona characteristics
        self._apply_persona_behavior()

    def _apply_persona_behavior(self):
        """Apply persona behavioral characteristics to wrapped agent."""
        # Create persona-driven configuration
        persona_config = PersonaConfiguration(persona_name=self.persona.name)
        config = self.adapter._create_persona_config(self.persona, persona_config, self.agent_type)

        # Apply to wrapped agent
        self.adapter._apply_config_to_agent(self.wrapped_agent, config)

    def execute_attack(self, target: str, scenario: str = "full_chain") -> Dict[str, Any]:
        """Execute attack with persona-driven behavior."""
        # Get persona's attack chain
        attack_chain = self.persona.get_attack_chain(scenario)

        # Extract techniques for the wrapped agent
        techniques = [phase['technique_id'] for phase in attack_chain]

        # Execute using wrapped agent
        if hasattr(self.wrapped_agent, 'execute_attack'):
            result = self.wrapped_agent.execute_attack(target, techniques)
        else:
            result = {'status': 'error', 'message': 'Wrapped agent has no execute_attack method'}

        # Add persona context to result
        result['persona_context'] = {
            'persona_name': self.persona.name,
            'mitre_id': self.persona.mitre_id,
            'sophistication': self.persona.sophistication_level.value,
            'stealth': self.persona.stealth_preference.value,
            'attack_chain_length': len(attack_chain)
        }

        return result

    def __getattr__(self, name):
        """Delegate unknown attributes to wrapped agent."""
        return getattr(self.wrapped_agent, name)


class ModernPersonaAgent(PersonaInjectableAgent):
    """
    Modernized agent that fully supports persona injection.
    """

    def __init__(self, legacy_agent: Any, agent_type: AgentType, persona_library: PersonaLibrary):
        self.legacy_agent = legacy_agent
        self.agent_type = agent_type
        self.persona_library = persona_library
        self.current_persona = None

    def inject_persona(self, persona: AttackerPersona) -> None:
        """Inject persona characteristics into the agent."""
        self.current_persona = persona
        logger.info(f"Injected {persona.name} persona into modernized agent")

    def execute_persona_driven_attack(self, target: str, scenario: str = "full_chain") -> Dict[str, Any]:
        """Execute attack following persona's behavioral patterns."""
        if not self.current_persona:
            raise ValueError("No persona injected. Call inject_persona() first.")

        # Use the new persona-driven agent
        from agent_bounty.agents.red_team_agent_v2 import RedTeamAgentWithPersona
        persona_agent = RedTeamAgentWithPersona(persona_name=self.current_persona.name)

        return persona_agent.execute_attack_campaign(
            target=target,
            scenario=scenario,
            auto_execute=True
        )

    def get_legacy_agent(self):
        """Access the original legacy agent."""
        return self.legacy_agent