<div align="center">
  <img src="assets/images/agent-bounty-logo.png" alt="Agent Bounty Logo" width="400">

  # Agent Bounty - Attacker Personas Library

  [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
  [![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1-red.svg)](https://attack.mitre.org/)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

  **Production-ready attacker personas library for Agent Bounty's autonomous security testing platform**

  [Website](https://agentbounty.ai) • [Documentation](docs/) • [Issues](https://github.com/AgentBounty/attacker-personas/issues) • [Discussions](https://github.com/AgentBounty/attacker-personas/discussions)
</div>

---

Production-ready attacker personas library for Agent Bounty's autonomous security testing platform. This library enables Red Team agents to simulate real-world Advanced Persistent Threat (APT) groups using authentic MITRE ATT&CK framework data.

## Overview

The Attacker Personas Library provides comprehensive threat actor simulation with **complete coverage of all 181 MITRE ATT&CK groups**:

- **Universal MITRE Coverage**: Immediate access to all 181 threat groups with intelligent behavioral modeling
- **Intelligent Auto-Generation**: Advanced algorithms automatically infer sophisticated characteristics for any MITRE group
- **Premium Personas**: 10 hand-tuned APT profiles with expert-researched behavioral characteristics
- **Real-time STIX Integration**: Automatic synchronization with official MITRE STIX 2.1 data
- **Advanced Behavioral Analysis**: Sophistication levels, stealth preferences, attack speeds, regional/industry targeting
- **Attack Campaign Execution**: Automated red team operations following authentic TTPs for any of the 181 groups
- **Bulk Operations**: CLI and programmatic tools for mass persona generation and management
- **Compliance Reporting**: Full MITRE ATT&CK technique mapping for security assessments
- **Scalable Architecture**: Supports new MITRE groups automatically as they're added to the framework

## System Architecture

<div align="center">
  <img src="assets/images/system-architecture.png" alt="High-Level System Architecture" width="800">
  <p><em>High-Level System Architecture - Complete Integration Flow</em></p>
</div>

## Architecture

```
agent_bounty/
├── attacker_personas/          # Core persona models and library
│   ├── persona.py             # AttackerPersona dataclass
│   ├── persona_library.py     # Pre-configured APT profiles
│   └── profiles/              # Individual APT configurations
├── threat_intelligence/        # MITRE ATT&CK integration
│   └── mitre_stix_client.py   # STIX 2.1 data parser
├── agents/                     # Enhanced Red Team agent
│   └── red_team_agent_v2.py   # Persona-driven attack execution
└── api/                        # FastAPI endpoints
    └── personas_controller.py  # REST API for persona management

```

## Data Model & Relationships

<div align="center">
  <img src="assets/images/data-model-relationships.png" alt="Data Model & Relationships" width="800">
  <p><em>Data Model & Relationships - Core System Data Architecture</em></p>
</div>

## Quick Start

<div align="center">
  <img src="assets/images/user-journey.png" alt="Complete End-to-End User Journey" width="800">
  <p><em>Complete End-to-End User Journey - From Setup to Attack Execution</em></p>
</div>

### Installation

```bash
# Clone repository
git clone <repository-url>
cd attacker-personas

# Install dependencies
pip install -r requirements.txt

# Initialize MITRE data (downloads ~100MB)
python -c "from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient; MITREStixClient()"
```

### Basic Usage

```python
from agent_bounty.attacker_personas.persona_library import PersonaLibrary
from agent_bounty.agents.red_team_agent_v2 import RedTeamAgentWithPersona

# Initialize persona library with auto-generation enabled
library = PersonaLibrary(auto_generate=True)

# Load any of the 181 MITRE groups - all work out of the box!
apt29 = library.get_persona("APT29")           # Premium hand-tuned persona
apt41 = library.get_persona("APT41")           # Auto-generated with intelligent behavior
turla = library.get_persona("Turla")           # Advanced Russian espionage group
volt_typhoon = library.get_persona("Volt Typhoon")  # Chinese infrastructure targeting

print(f"Loaded {apt41.name} with {len(apt41.techniques)} techniques")
print(f"Sophistication: {apt41.sophistication_level.value}")
print(f"Target industries: {apt41.target_industries}")

# Create Red Team agent with any persona
agent = RedTeamAgentWithPersona(persona_name="APT41")

# Execute attack campaign
campaign = agent.execute_attack_campaign(
    target="192.168.1.0/24",
    scenario="full_chain",
    auto_execute=True
)

# Generate report
report = agent.generate_attack_report()
print(f"Campaign success rate: {report['success_rate']}")

# Show statistics about all available groups
stats = library.get_auto_generated_stats()
print(f"Total available groups: {stats['total_mitre_groups']}")
```

### FastAPI Server

```python
from fastapi import FastAPI
from api.personas_controller import router

app = FastAPI(title="Agent Bounty Personas API")
app.include_router(router)

# Run with: uvicorn main:app --reload
```

## Complete Coverage: All 181 MITRE Groups Supported

The Attacker Personas Library provides comprehensive threat actor simulation capabilities with **full coverage of all 181 MITRE ATT&CK groups** through an intelligent multi-tier architecture:

### Full MITRE ATT&CK Coverage
- **Total MITRE Groups**: 181 threat groups (100% coverage)
- **Immediate Access**: Any MITRE group works out-of-the-box
- **Intelligent Auto-Generation**: Sophisticated behavioral inference for all groups
- **Real-Time Updates**: Automatically supports new MITRE groups as they're added

### Multi-Tier Implementation Strategy

<div align="center">
  <img src="assets/images/behavioral-inference-engine.png" alt="Behavioral Inference Engine Detail" width="800">
  <p><em>Behavioral Inference Engine Detail - Advanced Intelligence Analysis</em></p>
</div>

**Tier 1: Premium Personas (10 groups)**
- Hand-researched behavioral characteristics
- Sophistication levels, stealth preferences, attack speeds
- Target industry and regional preferences
- Operational parameters and motivations
- Quality over quantity approach for most critical threats

**Tier 2: Auto-Generated Personas (171 groups)**
- **Intelligent Behavioral Inference**: Advanced algorithms analyze MITRE data to infer characteristics
- **Sophistication Analysis**: Based on technique count, nation-state indicators, custom malware usage
- **Stealth Preference**: Inferred from obfuscation vs destructive technique ratios
- **Target Analysis**: Industry and regional focus extracted from descriptions and aliases
- **Motivation Detection**: Financial, espionage, disruption patterns automatically identified
- **Confidence Scoring**: Each generated persona includes quality confidence metrics

**Tier 3: Custom Personas (Unlimited)**
- User-created variants for specific scenarios
- Can inherit from any of the 181 base groups
- Customizable attributes for specialized testing needs

### Usage Patterns
```python
# Premium personas (hand-tuned behavioral characteristics)
apt29 = library.get_persona("APT29")  # Pre-configured with expert research

# Auto-generated personas (intelligent behavioral inference)
apt41 = library.get_persona("APT41")        # Advanced, Financial/Technology, 82 techniques
turla = library.get_persona("Turla")        # Advanced, Government targeting, 68 techniques
volt_typhoon = library.get_persona("Volt Typhoon")  # Chinese state-sponsored infrastructure
wizard_spider = library.get_persona("Wizard Spider")  # Ransomware operations

# All personas have sophisticated characteristics automatically:
print(f"Sophistication: {persona.sophistication_level.value}")
print(f"Stealth preference: {persona.stealth_preference.value}")
print(f"Target industries: {persona.target_industries}")
print(f"Attack motivations: {persona.motivations}")

# Custom personas
custom = library.create_custom_persona("Custom APT", base_persona="APT41")
```

### Automated Behavioral Inference

The system includes advanced algorithms that analyze MITRE data to automatically generate sophisticated behavioral characteristics:

<div align="center">
  <img src="assets/images/persona-generation-flow.png" alt="Persona Generation Flow" width="800">
  <p><em>Persona Generation Flow - Intelligent Auto-Generation Process</em></p>
</div>

**Intelligence Analysis Engine:**
- **Sophistication Detection**: Nation-state indicators, technique complexity, custom malware usage
- **Operational Security**: Stealth vs noisy technique ratios, detection evasion patterns
- **Attack Speed**: Automation vs persistence technique preferences
- **Geographic Targeting**: 8 regional keyword analysis sets
- **Industry Targeting**: 13 industry-specific keyword detection systems
- **Motivation Analysis**: Financial, espionage, disruption, destruction pattern recognition

**Quality Assurance:**
- Confidence scoring for each generated persona (0.1-0.95)
- Data completeness analysis (technique count, software usage, description quality)
- Validation against known threat intelligence patterns

## Pre-configured Premium APT Groups

| Group | MITRE ID | Sophistication | Primary Focus | Region |
|-------|----------|----------------|---------------|---------|
| **APT29** | G0016 | Advanced | Espionage | Russia |
| **APT28** | G0007 | Advanced | Information Warfare | Russia |
| **Lazarus Group** | G0032 | Advanced | Financial/Destructive | North Korea |
| **FIN7** | G0046 | High | Financial Theft | Global |
| **APT1** | G0006 | High | IP Theft | China |
| **Carbanak** | G0008 | High | Financial Institutions | Global |
| **APT33** | G0064 | High | Energy/Aviation | Iran |
| **Equation** | G0020 | Advanced | Cyber Espionage | Unknown |
| **DarkHydrus** | G0079 | Medium | Government Targeting | Middle East |
| **Sandworm Team** | G0034 | Advanced | Infrastructure Attacks | Russia |

### Expansion Candidates
High-value groups available for future premium configuration:
- **APT41** (82 techniques) - China financial/espionage hybrid
- **OilRig** (76 techniques) - Iran infrastructure targeting
- **Turla** (68 techniques) - Russia long-term espionage
- **APT38** (55 techniques) - North Korea financial operations
- **APT39** (53 techniques) - Iran telecommunications focus

## Bulk Generation and Management

### CLI Tools for Mass Operations

The library includes comprehensive command-line tools for bulk operations:

```bash
# Generate all 181 personas with intelligent behavioral inference
python scripts/generate_all_personas.py generate-all --format python

# Generate top 20 priority groups (by data completeness)
python scripts/generate_all_personas.py generate-priority --count 20

# Analyze coverage gaps and missing regional/industry focus
python scripts/generate_all_personas.py analyze

# Test specific persona generation
python scripts/generate_all_personas.py test "APT41"

# Show library statistics
python scripts/generate_all_personas.py stats
```

### Programmatic Bulk Operations

```python
from agent_bounty.attacker_personas.bulk_generator import BulkPersonaGenerator

# Initialize bulk generator
bulk_gen = BulkPersonaGenerator()

# Generate all missing personas (171 groups)
all_personas = bulk_gen.generate_all_missing_personas(min_confidence=0.3)

# Generate priority personas (highest data completeness)
priority_personas = bulk_gen.generate_priority_personas(count=50)

# Analyze coverage gaps
gap_analysis = bulk_gen.analyze_coverage_gaps()

# Create regional collections for targeted testing
regional_collections = bulk_gen.create_regional_collections()

# Export in multiple formats
bulk_gen.export_for_integration("python")  # Python code
bulk_gen.export_for_integration("json")    # JSON configuration
bulk_gen.export_for_integration("yaml")    # YAML configuration
```

### Performance Metrics

**Current Generation Results:**
- **Total Groups**: 181 (100% MITRE coverage)
- **Generation Success Rate**: >95%
- **Average Confidence Score**: 0.65-0.85
- **Processing Time**: ~2-3 minutes for all 181 groups
- **Data Quality**: Real MITRE techniques with intelligent behavioral inference

**Sample Auto-Generated Groups:**
```
✅ APT41: advanced sophistication, 82 techniques, Financial/Technology targeting
✅ Turla: advanced sophistication, 68 techniques, Government/Technology targeting
✅ OilRig: advanced sophistication, 76 techniques, Energy/Government targeting
✅ Kimsuky: advanced sophistication, 103 techniques, Government/Technology targeting
✅ Volt Typhoon: advanced sophistication, 81 techniques, Infrastructure targeting
✅ Wizard Spider: high sophistication, 64 techniques, Ransomware operations
```

## Persona Characteristics

### Sophistication Levels
- **Low**: Basic tools, simple techniques, high detection rate
- **Medium**: Mixed capabilities, moderate stealth
- **High**: Advanced tools, sophisticated techniques
- **Advanced**: Nation-state level, custom malware, very stealthy

### Attack Behaviors
- **Stealth Preference**: Noisy, Balanced, Stealthy
- **Attack Speed**: Slow, Moderate, Fast, Aggressive
- **Motivations**: Espionage, Financial, Disruption, Destruction

### Target Preferences
- **Industries**: Government, Technology, Financial, Healthcare, etc.
- **Regions**: Global, North America, Europe, Asia Pacific, etc.

## API Endpoints

### Persona Management

```http
GET /api/v1/personas
# List all available personas with filtering

GET /api/v1/personas/{persona_name}
# Get detailed persona information

POST /api/v1/personas/custom
# Create custom persona

GET /api/v1/personas/compare?persona1=APT29&persona2=APT28
# Compare two personas
```

### Attack Execution

```http
POST /api/v1/personas/attack
{
  "target": "192.168.1.0/24",
  "persona": "APT29",
  "scenario": "full_chain",
  "auto_execute": true,
  "max_duration_hours": 24
}
# Execute attack campaign

GET /api/v1/personas/attack/{campaign_id}/report
# Get campaign report
```

### MITRE Integration

```http
GET /api/v1/personas/mitre/groups
# List all MITRE groups

GET /api/v1/personas/techniques/{technique_id}
# Get technique details

POST /api/v1/personas/mitre/refresh
# Refresh MITRE data
```

## Attack Scenarios

<div align="center">
  <img src="assets/images/attack-campaign-flow.png" alt="Attack Campaign Execution Flow" width="800">
  <p><em>Attack Campaign Execution Flow - Persona-Driven Attack Orchestration</em></p>
</div>

### Full Kill Chain
Complete cyber attack simulation following MITRE ATT&CK tactics:
```
Reconnaissance → Initial Access → Execution → Persistence →
Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
```

### Ransomware Campaign
Focused on encryption and disruption:
```
Initial Access → Execution → Privilege Escalation →
Defense Evasion → Discovery → Lateral Movement → Impact
```

### Data Theft Operation
Espionage-focused campaign:
```
Initial Access → Execution → Persistence → Credential Access →
Discovery → Collection → Exfiltration
```

## Metrics and Reporting

### Campaign Metrics
- **Success Rate**: Percentage of successful technique executions
- **Detection Rate**: Percentage of techniques that triggered alerts
- **Risk Score**: 0-100 scale based on objectives achieved
- **Dwell Time**: Expected persistence duration based on persona
- **Data Exfiltrated**: Simulated data theft volume

### Security Recommendations
Automated generation of:
- Technique-specific mitigations
- Control gap analysis
- Detection improvement suggestions
- Incident response recommendations

## Security Considerations

### Defensive Use Only
This library is designed exclusively for:
- Red team exercises
- Security assessment and testing
- Blue team training
- Security control validation
- Compliance demonstrations

### Prohibited Uses
- Actual malicious attacks
- Unauthorized system access
- Credential harvesting
- Data theft or destruction
- Any illegal activities

### Safety Features
- Simulation-only attack execution
- No actual malware deployment
- Sandboxed testing environment required
- Comprehensive audit logging
- Permission-based access controls

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agent_bounty --cov-report=html

# Run specific test modules
pytest tests/attacker_personas/test_persona.py -v

# Integration tests (requires network access)
pytest tests/ -m integration
```

### Test Coverage
- **MITRE STIX Client**: 95% coverage
- **Persona Models**: 98% coverage
- **Red Team Agent**: 92% coverage
- **API Endpoints**: 89% coverage
- **Overall**: 93% coverage

## Data Sources

### MITRE ATT&CK STIX 2.1
- **Source**: https://github.com/mitre-attack/attack-stix-data
- **Format**: JSON (STIX 2.1 bundle)
- **Update Frequency**: Weekly automatic sync
- **Size**: ~100MB (40,000+ objects)

### Threat Intelligence
- Real-world APT group profiles
- Historical campaign analysis
- Industry targeting patterns
- Regional threat landscapes

## MITRE ATT&CK Integration

### Automatic Synchronization
```python
# Manual refresh
from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient

client = MITREStixClient()
client.refresh_cache()  # Downloads latest data
```

### Data Mapping
- **Groups**: `intrusion-set` → `AttackerPersona`
- **Techniques**: `attack-pattern` → Technique arsenal
- **Software**: `malware`/`tool` → Preferred tools
- **Relationships**: Links groups to their TTPs

## Advanced Usage

### Custom Persona Creation
```python
# Create custom persona from scratch
custom_apt = library.create_custom_persona(
    name="Custom Threat Actor",
    sophistication_level=SophisticationLevel.HIGH,
    stealth_preference=StealthLevel.STEALTHY,
    target_industries=["Healthcare", "Pharmaceuticals"],
    motivations=["espionage", "financial"],
    description="Healthcare-focused threat actor"
)

# Create variant of existing persona
apt29_variant = library.create_custom_persona(
    name="APT29 Healthcare Variant",
    base_persona="APT29",
    target_industries=["Healthcare"],
    description="APT29 variant targeting healthcare sector"
)
```

### Attack Chain Customization
```python
# Get persona's attack chain
chain = persona.get_attack_chain("full_chain")

# Modify for specific scenario
healthcare_chain = [
    phase for phase in chain
    if phase['tactic'] in ['initial-access', 'persistence', 'collection', 'exfiltration']
]

# Execute custom chain
agent.execute_custom_chain(healthcare_chain, target="hospital-network")
```

### Behavioral Analysis
```python
# Compare personas
comparison = library.compare_personas("APT29", "APT28")
print(f"Common techniques: {comparison['common_techniques']}")
print(f"APT29 unique: {comparison['persona1']['unique_techniques']}")

# Industry targeting analysis
financial_threats = library.get_personas_by_industry("Financial")
espionage_groups = library.get_personas_by_motivation("espionage")

# Sophistication analysis
nation_state = library.get_personas_by_sophistication(SophisticationLevel.ADVANCED)
```

## Performance Optimization

### Caching Strategy
- **STIX Data**: Local file cache with ETag validation
- **Persona Objects**: In-memory cache with configurable TTL
- **Attack Plans**: Pre-computed chains for common scenarios

### Resource Usage
- **Memory**: ~50MB for full MITRE dataset
- **Disk**: ~100MB for cached STIX data
- **Network**: Initial download only, weekly updates

### Scalability
- Supports concurrent persona loading
- Parallel attack campaign execution
- Database persistence for campaign history
- Horizontal scaling via Redis cache

## Troubleshooting

### Common Issues

**STIX Data Download Fails**
```bash
# Check network connectivity
ping raw.githubusercontent.com

# Manually download
wget https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Clear cache and retry
rm -rf data/mitre_attack/
python -c "from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient; MITREStixClient()"
```

**Persona Not Found**
```python
# List available personas
library = PersonaLibrary()
print(library.list_available_personas())

# Check MITRE groups
groups = library.list_all_mitre_groups()
print([g['name'] for g in groups])
```

**Memory Issues**
```python
# Disable caching for memory-constrained environments
library = PersonaLibrary(cache_personas=False)

# Use specific personas only
apt29 = library.get_persona("APT29")
library.clear_cache()  # Free memory
```

## Requirements

### System Requirements
- Python 3.10+
- 4GB RAM (recommended)
- 1GB disk space
- Internet connection (initial setup)

### Dependencies
- FastAPI 0.104+
- Pydantic 2.5+
- STIX2 3.0+
- Requests 2.31+
- PyTest 7.4+ (testing)

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd attacker-personas

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest

# Code formatting
black agent_bounty/
isort agent_bounty/
flake8 agent_bounty/
```

### Adding New Personas
1. Research the APT group's documented TTPs
2. Add configuration to `PERSONA_CONFIGS` in `persona_library.py`
3. Create profile file in `attacker_personas/profiles/`
4. Add test cases
5. Update documentation

### Contribution Guidelines
- Follow PEP 8 style guidelines
- Add type hints to all functions
- Include comprehensive tests (>80% coverage)
- Update documentation for new features
- Security-focused code reviews required

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided for educational and defensive security purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/agent-bounty/attacker-personas/issues)
- **Discussions**: [GitHub Discussions](https://github.com/agent-bounty/attacker-personas/discussions)
- **Security**: security@agentbounty.ai
- **See our platform in action**:  https://agentbounty.ai
- **Developed by Agent Bounty Team**: Wil, Ali, Mitul, & Usama

## Acknowledgments

- **MITRE Corporation** for the ATT&CK framework and STIX data
- **Security research community** for threat intelligence
- **Open source contributors** to the cybersecurity ecosystem

---

**Agent Bounty** - Autonomous Security Testing Platform
Making cybersecurity proactive, not reactive.
