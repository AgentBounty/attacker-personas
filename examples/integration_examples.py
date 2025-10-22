"""
Integration Examples
Real-world examples of integrating personas with existing Red Team agents
"""

from typing import Dict, List, Any
import time
import random

# Example existing agent classes (simulating common patterns)

class LegacyMetasploitAgent:
    """Example of a typical Metasploit-based red team agent."""

    def __init__(self):
        self.config = {"framework": "metasploit", "timeout": 30}
        self.active_sessions = []

    def configure(self, new_config: Dict[str, Any]):
        """Configure the agent."""
        self.config.update(new_config)

    def execute_exploit(self, target: str, exploit: str, payload: str) -> Dict[str, Any]:
        """Execute specific exploit."""
        # Simulate exploit execution
        success = random.choice([True, False])
        return {
            "status": "success" if success else "failed",
            "target": target,
            "exploit": exploit,
            "session_id": f"session_{len(self.active_sessions)}" if success else None
        }

    def get_available_exploits(self) -> List[str]:
        """Get available exploits."""
        return ["ms17_010_eternalblue", "apache_struts_rce", "web_delivery"]


class CustomPenetrationTestAgent:
    """Example of a custom penetration testing agent."""

    def __init__(self):
        self.settings = {"scan_intensity": "normal", "stealth_mode": False}
        self.discovered_services = []

    def set_config(self, config: Dict[str, Any]):
        """Set configuration."""
        self.settings.update(config)

    def perform_attack(self, target: str, techniques: List[str]) -> Dict[str, Any]:
        """Perform attack with specified techniques."""
        results = []
        for technique in techniques:
            # Simulate technique execution
            result = {
                "technique": technique,
                "status": random.choice(["success", "failed", "detected"]),
                "timestamp": time.time()
            }
            results.append(result)

        return {
            "target": target,
            "results": results,
            "overall_status": "completed"
        }

    def get_capabilities(self) -> List[str]:
        """Get agent capabilities."""
        return ["network_scan", "vulnerability_scan", "exploit", "post_exploit"]


class CobaltstrikeLikeAgent:
    """Example of a Cobalt Strike-like C2 agent."""

    def __init__(self):
        self.beacons = {}
        self.c2_config = {"sleep": 60, "jitter": 10}

    def update_config(self, config: Dict[str, Any]):
        """Update C2 configuration."""
        self.c2_config.update(config)

    def execute(self, target: str, commands: List[str]) -> Dict[str, Any]:
        """Execute commands on target."""
        beacon_id = f"beacon_{hash(target)}"

        if beacon_id not in self.beacons:
            # Simulate beacon deployment
            self.beacons[beacon_id] = {"target": target, "status": "active"}

        results = []
        for command in commands:
            # Simulate command execution
            results.append({
                "command": command,
                "output": f"Executed {command} on {target}",
                "status": "success"
            })

        return {
            "beacon_id": beacon_id,
            "target": target,
            "command_results": results
        }


# Integration examples using the persona system

def example_1_metasploit_integration():
    """Example 1: Integrating Metasploit agent with APT29 persona."""
    print("=== Example 1: Metasploit + APT29 Persona ===")

    from agent_bounty.integration.persona_adapter import PersonaAdapter, PersonaConfiguration, AgentType

    # Create existing agent
    metasploit_agent = LegacyMetasploitAgent()

    # Initialize persona adapter
    adapter = PersonaAdapter()

    # Register the agent
    adapter.register_agent("metasploit_1", metasploit_agent, AgentType.RED_TEAM)

    # Configure with APT29 persona (sophisticated, stealthy Russian group)
    persona_config = PersonaConfiguration(
        persona_name="APT29",
        stealth_mode=True,
        campaign_objectives=["credential_access", "persistence", "data_exfiltration"]
    )

    # Inject persona characteristics
    config = adapter.inject_persona_into_agent("metasploit_1", persona_config)

    print(f"✅ Injected APT29 persona into Metasploit agent")
    print(f"Sophistication: {config['sophistication_level']}")
    print(f"Stealth preference: {config['stealth_preference']}")
    print(f"Preferred techniques: {config['preferred_techniques'][:5]}")  # Show first 5

    # Agent now operates with APT29 behavioral characteristics
    # - Prefers stealthy techniques
    # - Targets government/technology sectors
    # - Uses sophisticated persistence methods

    return adapter, config


def example_2_wrapper_integration():
    """Example 2: Wrapping custom agent with Lazarus Group persona."""
    print("\n=== Example 2: Custom Agent + Lazarus Group Wrapper ===")

    from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType

    # Create existing agent
    pentest_agent = CustomPenetrationTestAgent()

    # Initialize adapter
    adapter = PersonaAdapter()

    # Wrap with Lazarus Group persona (North Korean, aggressive, financial motivation)
    wrapped_agent = adapter.create_persona_wrapper(
        pentest_agent,
        persona_name="Lazarus Group",
        agent_type=AgentType.PENETRATION_TEST
    )

    print(f"✅ Wrapped custom agent with Lazarus Group persona")

    # Execute attack with persona-driven behavior
    result = wrapped_agent.execute_attack(
        target="192.168.1.100",
        scenario="ransomware"  # Lazarus Group known for ransomware attacks
    )

    print(f"Persona context: {result.get('persona_context', {})}")

    # Wrapped agent now:
    # - Uses aggressive, noisy techniques (Lazarus Group characteristic)
    # - Focuses on financial/destructive objectives
    # - Exhibits North Korean APT patterns

    return wrapped_agent


def example_3_modernization():
    """Example 3: Modernizing Cobalt Strike-like agent."""
    print("\n=== Example 3: Modernizing C2 Agent ===")

    from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType
    from agent_bounty.attacker_personas.persona_library import PersonaLibrary

    # Create legacy agent
    c2_agent = CobaltstrikeLikeAgent()

    # Initialize components
    adapter = PersonaAdapter()
    library = PersonaLibrary(auto_generate=True)

    # Modernize the agent
    modern_agent = adapter.migrate_legacy_agent(c2_agent, AgentType.RED_TEAM)

    # Inject APT28 persona (Russian military, aggressive)
    apt28_persona = library.get_persona("APT28")
    modern_agent.inject_persona(apt28_persona)

    print(f"✅ Modernized C2 agent with APT28 persona")
    print(f"APT28 characteristics:")
    print(f"  Sophistication: {apt28_persona.sophistication_level.value}")
    print(f"  Stealth: {apt28_persona.stealth_preference.value}")
    print(f"  Target industries: {apt28_persona.target_industries[:3]}")

    # Execute persona-driven attack
    try:
        result = modern_agent.execute_persona_driven_attack(
            target="192.168.1.50",
            scenario="full_chain"
        )
        print(f"Campaign executed with {len(result.get('phases', []))} phases")
    except Exception as e:
        print(f"Note: {e}")  # Expected since we're using the new system

    return modern_agent


def example_4_multi_agent_campaign():
    """Example 4: Multi-agent APT campaign simulation."""
    print("\n=== Example 4: Multi-Agent APT Campaign ===")

    from agent_bounty.integration.persona_adapter import PersonaAdapter, PersonaConfiguration, AgentType

    # Create multiple agents for different phases
    recon_agent = CustomPenetrationTestAgent()
    exploit_agent = LegacyMetasploitAgent()
    c2_agent = CobaltstrikeLikeAgent()

    # Initialize adapter
    adapter = PersonaAdapter()

    # Register all agents
    adapter.register_agent("reconnaissance", recon_agent, AgentType.VULNERABILITY_SCANNER)
    adapter.register_agent("exploitation", exploit_agent, AgentType.RED_TEAM)
    adapter.register_agent("persistence", c2_agent, AgentType.RED_TEAM)

    # Configure campaign - simulating APT29 multi-stage attack
    campaign_config = {
        'campaign_id': 'apt29_healthcare_2024',
        'target': '192.168.100.0/24',  # Healthcare network
        'agent_assignments': [
            {
                'agent_id': 'reconnaissance',
                'persona_name': 'APT29',
                'objectives': ['discovery', 'reconnaissance'],
                'target': '192.168.100.0/24',
                'techniques': ['T1595.002', 'T1590.001', 'T1589.002']  # Network scanning, DNS, WHOIS
            },
            {
                'agent_id': 'exploitation',
                'persona_name': 'APT29',
                'objectives': ['initial_access'],
                'target': '192.168.100.10',  # Web server
                'techniques': ['T1566.002', 'T1078.004']  # Spearphishing, cloud accounts
            },
            {
                'agent_id': 'persistence',
                'persona_name': 'APT29',
                'objectives': ['persistence', 'privilege_escalation'],
                'target': '192.168.100.10',
                'techniques': ['T1547.001', 'T1055.012']  # Registry run keys, process hollowing
            }
        ]
    }

    # Execute coordinated campaign
    try:
        results = adapter.orchestrate_multi_agent_campaign(campaign_config)
        print(f"✅ Executed multi-agent campaign: {results['campaign_id']}")
        print(f"Agents involved: {len(results['agent_results'])}")
        for log_entry in results['coordination_log']:
            print(f"  - {log_entry}")
    except Exception as e:
        print(f"Campaign simulation: {e}")

    return results


def example_5_persona_recommendations():
    """Example 5: Getting persona recommendations for specific targets."""
    print("\n=== Example 5: Persona Recommendations ===")

    from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType

    adapter = PersonaAdapter()

    # Different target scenarios
    target_scenarios = [
        {
            'name': 'Financial Institution',
            'industry': 'Financial',
            'region': 'North America',
            'objectives': ['financial', 'data_theft']
        },
        {
            'name': 'Government Agency',
            'industry': 'Government',
            'region': 'Europe',
            'objectives': ['espionage', 'intelligence_gathering']
        },
        {
            'name': 'Healthcare Provider',
            'industry': 'Healthcare',
            'region': 'Global',
            'objectives': ['data_theft', 'disruption']
        }
    ]

    for scenario in target_scenarios:
        print(f"\n🎯 Target: {scenario['name']}")
        recommendations = adapter.get_persona_recommendations(
            AgentType.RED_TEAM,
            scenario
        )
        print(f"Recommended personas: {', '.join(recommendations[:3])}")


def example_6_compatibility_analysis():
    """Example 6: Analyzing agent compatibility."""
    print("\n=== Example 6: Agent Compatibility Analysis ===")

    from agent_bounty.integration.migration_toolkit import AgentCompatibilityAnalyzer

    analyzer = AgentCompatibilityAnalyzer()

    # Analyze different agent types
    agents_to_analyze = [
        ("MetasploitAgent", LegacyMetasploitAgent()),
        ("PenTestAgent", CustomPenetrationTestAgent()),
        ("C2Agent", CobaltstrikeLikeAgent())
    ]

    for agent_name, agent in agents_to_analyze:
        migration_plan = analyzer.analyze_agent(agent, agent_name)

        print(f"\n📊 Analysis: {agent_name}")
        print(f"  Compatibility Score: {migration_plan.compatibility_score:.2f}")
        print(f"  Migration Strategy: {migration_plan.migration_strategy}")
        print(f"  Agent Type: {migration_plan.agent_type.value}")
        print(f"  Required Changes: {len(migration_plan.required_changes)}")
        print(f"  Recommended Personas: {', '.join(migration_plan.recommended_personas)}")


def run_all_examples():
    """Run all integration examples."""
    print("🚀 Running All Integration Examples")
    print("=" * 50)

    try:
        # Example 1: Direct injection
        adapter1, config1 = example_1_metasploit_integration()

        # Example 2: Wrapper pattern
        wrapped_agent = example_2_wrapper_integration()

        # Example 3: Modernization
        modern_agent = example_3_modernization()

        # Example 4: Multi-agent campaign
        campaign_results = example_4_multi_agent_campaign()

        # Example 5: Recommendations
        example_5_persona_recommendations()

        # Example 6: Compatibility analysis
        example_6_compatibility_analysis()

        print("\n✅ All examples completed successfully!")
        print("\nNext steps:")
        print("1. Adapt these patterns to your existing agents")
        print("2. Use the migration toolkit to analyze your agents")
        print("3. Choose the appropriate integration strategy")
        print("4. Test with recommended personas")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("Note: Some examples require the full persona system to be initialized")


if __name__ == "__main__":
    run_all_examples()