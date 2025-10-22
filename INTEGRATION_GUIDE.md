# Integration Guide: Connecting Personas with Existing Red Team Agents

This guide shows how to integrate the Attacker Personas Library with your existing Red Team agents, penetration testing tools, and security automation systems.

## Overview

The integration system provides multiple approaches to connect personas with existing agents:

1. **Direct Injection**: Modify existing agent configurations with persona characteristics
2. **Wrapper Pattern**: Wrap existing agents with persona behavior without code changes
3. **Modernization**: Upgrade legacy agents to fully support persona-driven operations
4. **Multi-Agent Orchestration**: Coordinate multiple agents in persona-driven campaigns

## Quick Start Integration

### Step 1: Analyze Your Existing Agent

```python
from agent_bounty.integration.migration_toolkit import AgentCompatibilityAnalyzer

# Analyze your existing agent
analyzer = AgentCompatibilityAnalyzer()
migration_plan = analyzer.analyze_agent(your_existing_agent, "my_agent")

print(f"Compatibility Score: {migration_plan.compatibility_score}")
print(f"Recommended Strategy: {migration_plan.migration_strategy}")
print(f"Required Changes: {migration_plan.required_changes}")
```

### Step 2: Choose Integration Approach

Based on the compatibility score:
- **Score 0.8+**: Use **Direct Injection** (easiest)
- **Score 0.5-0.8**: Use **Wrapper Pattern** (minimal changes)
- **Score <0.5**: Use **Modernization** (most comprehensive)

### Step 3: Implement Integration

#### Option A: Direct Injection (Highest Compatibility)

```python
from agent_bounty.integration.persona_adapter import PersonaAdapter, PersonaConfiguration, AgentType

# Initialize adapter
adapter = PersonaAdapter()

# Register your agent
adapter.register_agent("my_agent", your_existing_agent, AgentType.RED_TEAM)

# Inject persona
persona_config = PersonaConfiguration(
    persona_name="APT29",  # Any of the 181 MITRE groups
    stealth_mode=True,
    campaign_objectives=["credential_access", "persistence"]
)

config = adapter.inject_persona_into_agent("my_agent", persona_config)

# Your agent now operates with APT29 characteristics
result = your_existing_agent.execute_attack(target="192.168.1.100")
```

#### Option B: Wrapper Pattern (Medium Compatibility)

```python
from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType

adapter = PersonaAdapter()

# Wrap your agent with persona behavior
wrapped_agent = adapter.create_persona_wrapper(
    your_existing_agent,
    persona_name="Lazarus Group",  # North Korean group
    agent_type=AgentType.RED_TEAM
)

# Execute with persona-driven behavior
result = wrapped_agent.execute_attack(
    target="192.168.1.100",
    scenario="ransomware"  # Lazarus Group specialty
)

# Access original agent if needed
original_agent = wrapped_agent.wrapped_agent
```

#### Option C: Modernization (Full Upgrade)

```python
from agent_bounty.integration.persona_adapter import PersonaAdapter, AgentType
from agent_bounty.attacker_personas.persona_library import PersonaLibrary

# Modernize your agent
adapter = PersonaAdapter()
modern_agent = adapter.migrate_legacy_agent(your_existing_agent, AgentType.RED_TEAM)

# Inject sophisticated persona
library = PersonaLibrary(auto_generate=True)
persona = library.get_persona("APT41")  # Chinese dual-use group
modern_agent.inject_persona(persona)

# Execute persona-driven attack
result = modern_agent.execute_persona_driven_attack(
    target="192.168.1.100",
    scenario="full_chain"
)
```

## Common Integration Patterns

### Pattern 1: Metasploit Integration

```python
# For Metasploit-based agents
class MetasploitAgent:
    def execute_exploit(self, target, exploit, payload):
        # Your existing Metasploit logic
        pass

# Integration
adapter = PersonaAdapter()
adapter.register_agent("msf_agent", metasploit_agent, AgentType.PENETRATION_TEST)

persona_config = PersonaConfiguration(
    persona_name="FIN7",  # Financial cybercriminal group
    technique_filter=["T1566.002", "T1059.001", "T1055"]  # Specific techniques
)

adapter.inject_persona_into_agent("msf_agent", persona_config)
```

### Pattern 2: Custom Scanner Integration

```python
# For vulnerability scanners
class VulnScanner:
    def scan(self, target):
        # Your scanning logic
        pass

    def exploit(self, target, vulns):
        # Your exploitation logic
        pass

# Integration with wrapper
wrapped_scanner = adapter.create_persona_wrapper(
    vuln_scanner,
    persona_name="OilRig",  # Iranian group targeting infrastructure
    agent_type=AgentType.VULNERABILITY_SCANNER
)

# Scanner now uses OilRig's sophisticated techniques and targeting preferences
```

### Pattern 3: C2 Framework Integration

```python
# For C2 frameworks (Cobalt Strike, Empire, etc.)
class C2Agent:
    def deploy_beacon(self, target):
        # Your C2 deployment logic
        pass

    def execute_commands(self, beacon_id, commands):
        # Your command execution logic
        pass

# Modernization approach
modern_c2 = adapter.migrate_legacy_agent(c2_agent, AgentType.RED_TEAM)

# Inject nation-state persona
apt28_persona = library.get_persona("APT28")  # Russian military intelligence
modern_c2.inject_persona(apt28_persona)

# C2 now operates with APT28's aggressive, information warfare characteristics
```

## Multi-Agent Campaign Orchestration

Coordinate multiple agents in a realistic APT campaign:

```python
# Define campaign with multiple specialized agents
campaign_config = {
    'campaign_id': 'healthcare_apt29_2024',
    'target': '192.168.100.0/24',
    'agent_assignments': [
        {
            'agent_id': 'reconnaissance_agent',
            'persona_name': 'APT29',
            'objectives': ['discovery', 'reconnaissance'],
            'techniques': ['T1595.002', 'T1590.001']  # Network/DNS recon
        },
        {
            'agent_id': 'initial_access_agent',
            'persona_name': 'APT29',
            'objectives': ['initial_access'],
            'techniques': ['T1566.002', 'T1078.004']  # Spearphishing, cloud accounts
        },
        {
            'agent_id': 'persistence_agent',
            'persona_name': 'APT29',
            'objectives': ['persistence', 'privilege_escalation'],
            'techniques': ['T1547.001', 'T1055.012']  # Registry persistence, process hollowing
        }
    ]
}

# Execute coordinated campaign
results = adapter.orchestrate_multi_agent_campaign(campaign_config)
```

## Persona Recommendations

Get persona recommendations based on your target environment:

```python
# Define target characteristics
target_info = {
    'industry': 'Financial',
    'region': 'North America',
    'objectives': ['financial', 'data_theft'],
    'security_maturity': 'high'
}

# Get recommendations
recommendations = adapter.get_persona_recommendations(
    AgentType.RED_TEAM,
    target_info
)

print(f"Recommended personas: {recommendations}")
# Output: ['FIN7', 'Carbanak', 'APT1', 'Lazarus Group']
```

## Advanced Integration Features

### Technique Filtering

Limit personas to specific techniques:

```python
persona_config = PersonaConfiguration(
    persona_name="APT33",
    technique_filter=[
        "T1566.001",  # Spearphishing attachment
        "T1059.001",  # PowerShell
        "T1055.012"   # Process hollowing
    ],
    stealth_mode=True
)
```

### Behavioral Overrides

Override persona characteristics for specific scenarios:

```python
persona_config = PersonaConfiguration(
    persona_name="Sandworm Team",
    behavior_override={
        'stealth_preference': 'stealthy',  # Override normally noisy group
        'attack_speed': 'slow',           # Override normally fast group
        'detection_sensitivity': 0.9      # Make more cautious
    }
)
```

### Campaign Objectives

Define specific objectives for the persona:

```python
persona_config = PersonaConfiguration(
    persona_name="APT41",
    campaign_objectives=[
        "credential_access",
        "data_exfiltration",
        "financial_gain",
        "long_term_persistence"
    ]
)
```

## Migration Helper

Use the migration helper for streamlined integration:

```python
from agent_bounty.integration.migration_toolkit import MigrationHelper

helper = MigrationHelper()

# Quick integration with automatic strategy selection
result = helper.quick_integration(
    agent=your_existing_agent,
    agent_id="my_agent",
    preferred_persona="APT29"
)

print(f"Integration status: {result['integration_status']}")
print(f"Instructions: {result['instructions']}")

# Generate code examples
if result['migration_plan'].migration_strategy == "inject":
    code = helper.generate_integration_code("YourAgentClass", result['migration_plan'])
    print("Generated integration code:")
    print(code)
```

## Common Agent Types and Recommended Personas

### Red Team Agents
- **Sophisticated Operations**: APT29, APT28, Equation
- **Financial Attacks**: FIN7, Carbanak, Lazarus Group
- **Infrastructure Targeting**: Sandworm Team, APT33, OilRig

### Penetration Testing
- **Government Targets**: APT1, APT29, DarkHydrus
- **Corporate Targets**: FIN7, APT28, APT41
- **Critical Infrastructure**: Sandworm Team, APT33

### Vulnerability Scanners
- **Comprehensive Scans**: APT41, Kimsuky (high technique count)
- **Targeted Scans**: OilRig, APT33 (specific industry focus)

## Troubleshooting

### Common Issues

**Issue**: Agent not responding to persona configuration
```python
# Solution: Check if agent has configuration methods
if hasattr(agent, 'set_configuration'):
    # Direct configuration possible
elif hasattr(agent, 'config'):
    # Configuration via attribute
else:
    # Use wrapper approach instead
```

**Issue**: Techniques not matching agent capabilities
```python
# Solution: Filter techniques to agent's capabilities
available_techniques = agent.get_available_techniques()
persona_config = PersonaConfiguration(
    persona_name="APT29",
    technique_filter=available_techniques  # Only use what agent supports
)
```

**Issue**: Agent interface incompatible
```python
# Solution: Use modernization approach
modern_agent = adapter.migrate_legacy_agent(agent, AgentType.RED_TEAM)
# Implement required interface methods on modern_agent
```

## Best Practices

1. **Start Small**: Begin with one persona on one agent
2. **Test Thoroughly**: Validate persona behavior matches expectations
3. **Monitor Performance**: Check that persona integration doesn't impact performance
4. **Document Changes**: Record what personas work best with which agents
5. **Iterate**: Refine persona configurations based on results

## Next Steps

1. Analyze your existing agents using `AgentCompatibilityAnalyzer`
2. Choose appropriate integration strategy based on compatibility scores
3. Start with high-compatibility agents and Direct Injection approach
4. Gradually expand to more agents using Wrapper or Modernization patterns
5. Experiment with multi-agent campaigns for realistic APT simulations

The integration system is designed to work with any existing Red Team agent architecture while providing the sophisticated behavioral modeling of real threat actors.