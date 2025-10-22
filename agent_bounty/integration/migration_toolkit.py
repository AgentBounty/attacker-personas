"""
Migration Toolkit for Existing Red Team Agents
Provides tools and examples for integrating personas with existing agents
"""

import logging
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass
import inspect

from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType, PersonaConfiguration
from agent_bounty.attacker_personas.persona_library import PersonaLibrary

logger = logging.getLogger(__name__)


@dataclass
class AgentMigrationPlan:
    """Plan for migrating an existing agent to use personas."""
    agent_id: str
    agent_type: AgentType
    migration_strategy: str  # "wrap", "inject", "modernize"
    compatibility_score: float
    required_changes: List[str]
    recommended_personas: List[str]


class AgentCompatibilityAnalyzer:
    """Analyzes existing agents for persona compatibility."""

    def analyze_agent(self, agent: Any, agent_id: str) -> AgentMigrationPlan:
        """
        Analyze an existing agent for persona compatibility.

        Args:
            agent: The agent instance to analyze
            agent_id: Identifier for the agent

        Returns:
            Migration plan with recommendations
        """
        # Analyze agent interface
        interface_score = self._analyze_interface(agent)
        config_score = self._analyze_configuration_support(agent)
        execution_score = self._analyze_execution_methods(agent)

        overall_score = (interface_score + config_score + execution_score) / 3

        # Determine migration strategy
        if overall_score >= 0.8:
            strategy = "inject"  # Can directly inject personas
        elif overall_score >= 0.5:
            strategy = "wrap"    # Wrap with persona adapter
        else:
            strategy = "modernize"  # Needs significant modernization

        # Determine agent type
        agent_type = self._determine_agent_type(agent)

        # Generate required changes
        required_changes = self._generate_required_changes(agent, strategy, overall_score)

        # Recommend personas
        recommended_personas = self._recommend_initial_personas(agent_type)

        return AgentMigrationPlan(
            agent_id=agent_id,
            agent_type=agent_type,
            migration_strategy=strategy,
            compatibility_score=overall_score,
            required_changes=required_changes,
            recommended_personas=recommended_personas
        )

    def _analyze_interface(self, agent: Any) -> float:
        """Analyze agent's interface compatibility."""
        score = 0.0

        # Check for common execution methods
        execution_methods = ['execute', 'execute_attack', 'run', 'start', 'perform_attack']
        for method in execution_methods:
            if hasattr(agent, method) and callable(getattr(agent, method)):
                score += 0.3
                break

        # Check for configuration methods
        config_methods = ['configure', 'set_config', 'set_configuration', 'update_config']
        for method in config_methods:
            if hasattr(agent, method) and callable(getattr(agent, method)):
                score += 0.3
                break

        # Check for technique/capability methods
        capability_methods = ['get_techniques', 'get_capabilities', 'list_techniques']
        for method in capability_methods:
            if hasattr(agent, method) and callable(getattr(agent, method)):
                score += 0.2
                break

        # Check for status/reporting methods
        status_methods = ['get_status', 'get_report', 'get_results']
        for method in status_methods:
            if hasattr(agent, method) and callable(getattr(agent, method)):
                score += 0.2
                break

        return min(score, 1.0)

    def _analyze_configuration_support(self, agent: Any) -> float:
        """Analyze agent's configuration capabilities."""
        score = 0.0

        # Check for configuration attributes
        config_attrs = ['config', 'configuration', 'settings', 'options']
        for attr in config_attrs:
            if hasattr(agent, attr):
                score += 0.25

        # Check if configuration is writable
        for attr in config_attrs:
            if hasattr(agent, attr):
                try:
                    original = getattr(agent, attr)
                    setattr(agent, attr, original)  # Test if writable
                    score += 0.25
                    break
                except (AttributeError, TypeError):
                    pass

        return min(score, 1.0)

    def _analyze_execution_methods(self, agent: Any) -> float:
        """Analyze agent's execution method signatures."""
        score = 0.0

        execution_methods = ['execute', 'execute_attack', 'run', 'perform_attack']
        for method_name in execution_methods:
            if hasattr(agent, method_name):
                method = getattr(agent, method_name)
                if callable(method):
                    try:
                        # Analyze method signature
                        sig = inspect.signature(method)
                        params = list(sig.parameters.keys())

                        # Good if it accepts target parameter
                        if any(p in params for p in ['target', 'targets']):
                            score += 0.3

                        # Good if it accepts techniques/commands
                        if any(p in params for p in ['techniques', 'commands', 'actions']):
                            score += 0.3

                        # Good if it accepts configuration
                        if any(p in params for p in ['config', 'options', 'settings']):
                            score += 0.2

                        # Good if it has kwargs for flexibility
                        if any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values()):
                            score += 0.2

                        break
                    except (ValueError, TypeError):
                        # Signature inspection failed, give partial credit
                        score += 0.1

        return min(score, 1.0)

    def _determine_agent_type(self, agent: Any) -> AgentType:
        """Determine the type of agent based on its characteristics."""
        # Check class name and methods for hints
        class_name = agent.__class__.__name__.lower()
        method_names = [name for name in dir(agent) if callable(getattr(agent, name))]

        if any(term in class_name for term in ['redteam', 'red_team', 'attack']):
            return AgentType.RED_TEAM
        elif any(term in class_name for term in ['pentest', 'penetration']):
            return AgentType.PENETRATION_TEST
        elif any(term in class_name for term in ['vuln', 'scanner']):
            return AgentType.VULNERABILITY_SCANNER
        elif any(term in class_name for term in ['simulate', 'emulate']):
            return AgentType.ATTACK_SIMULATOR
        else:
            # Default to red team if uncertain
            return AgentType.RED_TEAM

    def _generate_required_changes(self, agent: Any, strategy: str, score: float) -> List[str]:
        """Generate list of required changes for migration."""
        changes = []

        if strategy == "inject":
            if score < 0.9:
                changes.append("Add persona configuration support")
            if not hasattr(agent, 'execute_attack'):
                changes.append("Standardize execution method naming")

        elif strategy == "wrap":
            changes.append("Implement PersonaWrappedAgent wrapper")
            if score < 0.7:
                changes.append("Add configuration bridge methods")

        elif strategy == "modernize":
            changes.append("Implement PersonaInjectableAgent interface")
            changes.append("Add persona-driven execution methods")
            changes.append("Modernize configuration system")
            changes.append("Add MITRE ATT&CK technique support")

        # Common improvements
        if not any(hasattr(agent, method) for method in ['get_techniques', 'get_capabilities']):
            changes.append("Add technique enumeration capability")

        if not any(hasattr(agent, method) for method in ['get_report', 'get_results']):
            changes.append("Add reporting/results capability")

        return changes

    def _recommend_initial_personas(self, agent_type: AgentType) -> List[str]:
        """Recommend initial personas for testing."""
        if agent_type == AgentType.RED_TEAM:
            return ["APT29", "APT28", "FIN7"]
        elif agent_type == AgentType.PENETRATION_TEST:
            return ["APT1", "Carbanak", "APT33"]
        elif agent_type == AgentType.VULNERABILITY_SCANNER:
            return ["DarkHydrus", "OilRig"]
        else:
            return ["APT29", "FIN7", "Lazarus Group"]


class ExistingAgentExamples:
    """Examples of how to integrate with common agent patterns."""

    @staticmethod
    def integrate_metasploit_agent(metasploit_agent):
        """Example: Integrate with Metasploit-based agent."""
        adapter = PersonaAdapter()

        # Register the agent
        adapter.register_agent("metasploit_1", metasploit_agent, AgentType.PENETRATION_TEST)

        # Inject APT29 persona
        persona_config = PersonaConfiguration(
            persona_name="APT29",
            stealth_mode=True,
            campaign_objectives=["credential_access", "persistence"]
        )

        config = adapter.inject_persona_into_agent("metasploit_1", persona_config)

        return config

    @staticmethod
    def integrate_custom_scanner(scanner_agent):
        """Example: Integrate with custom vulnerability scanner."""
        adapter = PersonaAdapter()

        # Wrap the scanner with persona behavior
        wrapped_scanner = adapter.create_persona_wrapper(
            scanner_agent,
            persona_name="OilRig",
            agent_type=AgentType.VULNERABILITY_SCANNER
        )

        return wrapped_scanner

    @staticmethod
    def integrate_cobaltstrike_agent(cs_agent):
        """Example: Integrate with Cobalt Strike agent."""
        adapter = PersonaAdapter()

        # Create modernized version
        modern_agent = adapter.migrate_legacy_agent(cs_agent, AgentType.RED_TEAM)

        # Inject sophisticated persona
        from agent_bounty.attacker_personas.persona_library import PersonaLibrary
        library = PersonaLibrary()
        apt28_persona = library.get_persona("APT28")

        modern_agent.inject_persona(apt28_persona)

        return modern_agent

    @staticmethod
    def multi_agent_apt_simulation():
        """Example: Multi-agent APT simulation."""
        adapter = PersonaAdapter()

        # Simulate APT campaign with multiple specialized agents
        campaign_config = {
            'campaign_id': 'apt29_campaign_2024',
            'target': '192.168.1.0/24',
            'agent_assignments': [
                {
                    'agent_id': 'reconnaissance_agent',
                    'persona_name': 'APT29',
                    'objectives': ['discovery', 'reconnaissance'],
                    'techniques': ['T1595', 'T1590', 'T1589']
                },
                {
                    'agent_id': 'initial_access_agent',
                    'persona_name': 'APT29',
                    'objectives': ['initial_access'],
                    'techniques': ['T1566.002', 'T1078']
                },
                {
                    'agent_id': 'persistence_agent',
                    'persona_name': 'APT29',
                    'objectives': ['persistence', 'privilege_escalation'],
                    'techniques': ['T1547.001', 'T1055']
                }
            ]
        }

        return adapter.orchestrate_multi_agent_campaign(campaign_config)


class MigrationHelper:
    """Helper class to assist with agent migration."""

    def __init__(self):
        self.analyzer = AgentCompatibilityAnalyzer()
        self.adapter = PersonaAdapter()

    def quick_integration(self, agent: Any, agent_id: str, preferred_persona: str = "APT29") -> Dict[str, Any]:
        """
        Quick integration for common agent patterns.

        Args:
            agent: Existing agent to integrate
            agent_id: Identifier for the agent
            preferred_persona: Persona to apply initially

        Returns:
            Integration results and instructions
        """
        # Analyze the agent
        migration_plan = self.analyzer.analyze_agent(agent, agent_id)

        result = {
            'migration_plan': migration_plan,
            'integration_status': 'pending',
            'instructions': [],
            'code_examples': []
        }

        try:
            if migration_plan.migration_strategy == "inject":
                # Direct injection
                self.adapter.register_agent(agent_id, agent, migration_plan.agent_type)
                persona_config = PersonaConfiguration(persona_name=preferred_persona)
                config = self.adapter.inject_persona_into_agent(agent_id, persona_config)

                result['integration_status'] = 'success'
                result['config'] = config
                result['instructions'].append("Agent successfully configured with persona")

            elif migration_plan.migration_strategy == "wrap":
                # Wrapper approach
                wrapped_agent = self.adapter.create_persona_wrapper(
                    agent, preferred_persona, migration_plan.agent_type
                )

                result['integration_status'] = 'success'
                result['wrapped_agent'] = wrapped_agent
                result['instructions'].append("Agent wrapped with persona behavior")

            else:  # modernize
                # Modernization required
                modern_agent = self.adapter.migrate_legacy_agent(agent, migration_plan.agent_type)

                result['integration_status'] = 'partial'
                result['modern_agent'] = modern_agent
                result['instructions'].extend([
                    "Agent partially modernized",
                    "Manual implementation of required changes needed",
                    f"Required changes: {', '.join(migration_plan.required_changes)}"
                ])

        except Exception as e:
            result['integration_status'] = 'error'
            result['error'] = str(e)
            result['instructions'].append(f"Integration failed: {e}")

        return result

    def generate_integration_code(self, agent_class_name: str, migration_plan: AgentMigrationPlan) -> str:
        """Generate code example for integration."""
        if migration_plan.migration_strategy == "inject":
            return f"""
# Direct injection example for {agent_class_name}
from agent_bounty.integration.persona_adapter import PersonaAdapter, PersonaConfiguration, AgentType

# Initialize adapter
adapter = PersonaAdapter()

# Register your agent
my_agent = {agent_class_name}()
adapter.register_agent("my_agent", my_agent, AgentType.{migration_plan.agent_type.name})

# Inject persona
persona_config = PersonaConfiguration(
    persona_name="{migration_plan.recommended_personas[0]}",
    stealth_mode=True
)
config = adapter.inject_persona_into_agent("my_agent", persona_config)

# Execute persona-driven attack
result = my_agent.execute_attack(target="192.168.1.100", techniques=config['preferred_techniques'])
"""

        elif migration_plan.migration_strategy == "wrap":
            return f"""
# Wrapper example for {agent_class_name}
from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType

# Initialize adapter
adapter = PersonaAdapter()

# Wrap your agent
my_agent = {agent_class_name}()
wrapped_agent = adapter.create_persona_wrapper(
    my_agent,
    persona_name="{migration_plan.recommended_personas[0]}",
    agent_type=AgentType.{migration_plan.agent_type.name}
)

# Execute with persona behavior
result = wrapped_agent.execute_attack(target="192.168.1.100", scenario="full_chain")
"""

        else:  # modernize
            return f"""
# Modernization example for {agent_class_name}
from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType
from agent_bounty.attacker_personas.persona_library import PersonaLibrary

# Initialize components
adapter = PersonaAdapter()
library = PersonaLibrary()

# Modernize your agent
my_agent = {agent_class_name}()
modern_agent = adapter.migrate_legacy_agent(my_agent, AgentType.{migration_plan.agent_type.name})

# Inject persona
persona = library.get_persona("{migration_plan.recommended_personas[0]}")
modern_agent.inject_persona(persona)

# Execute persona-driven attack
result = modern_agent.execute_persona_driven_attack(target="192.168.1.100", scenario="full_chain")

# Required changes to implement:
# {chr(10).join(f'# - {change}' for change in migration_plan.required_changes)}
"""