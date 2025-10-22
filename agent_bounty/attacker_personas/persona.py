"""
Attacker Persona Core Models
Represents threat actors with MITRE ATT&CK TTPs
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import random
import logging

logger = logging.getLogger(__name__)


class SophisticationLevel(str, Enum):
    """Threat actor sophistication levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"


class StealthLevel(str, Enum):
    """Operational security preference."""
    NOISY = "noisy"
    BALANCED = "balanced"
    STEALTHY = "stealthy"


class AttackSpeed(str, Enum):
    """Attack execution speed preference."""
    SLOW = "slow"         # Days between actions
    MODERATE = "moderate" # Hours between actions
    FAST = "fast"        # Minutes between actions
    AGGRESSIVE = "aggressive"  # Continuous actions


@dataclass
class AttackerPersona:
    """
    Represents a real-world threat actor with MITRE ATT&CK TTPs.

    This class encapsulates the identity, capabilities, and behavioral
    characteristics of an Advanced Persistent Threat (APT) group or
    other threat actor.
    """

    # Core Identity
    stix_id: str                    # STIX intrusion-set ID
    mitre_id: str                   # G0016, G0007, etc.
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""

    # MITRE ATT&CK TTPs
    tactics: List[str] = field(default_factory=list)
    techniques: List[Dict] = field(default_factory=list)  # [{id, name, tactic}, ...]
    software: List[Dict] = field(default_factory=list)    # [{id, name, type}, ...]

    # Behavioral Characteristics
    sophistication_level: SophisticationLevel = SophisticationLevel.MEDIUM
    stealth_preference: StealthLevel = StealthLevel.BALANCED
    attack_speed: AttackSpeed = AttackSpeed.MODERATE
    target_industries: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    motivations: List[str] = field(default_factory=list)  # ["financial", "espionage", "disruption"]

    # Attack Preferences (derived from techniques)
    preferred_initial_access: List[str] = field(default_factory=list)
    preferred_persistence: List[str] = field(default_factory=list)
    preferred_privilege_escalation: List[str] = field(default_factory=list)
    preferred_defense_evasion: List[str] = field(default_factory=list)
    preferred_credential_access: List[str] = field(default_factory=list)
    preferred_discovery: List[str] = field(default_factory=list)
    preferred_lateral_movement: List[str] = field(default_factory=list)
    preferred_collection: List[str] = field(default_factory=list)
    preferred_command_control: List[str] = field(default_factory=list)
    preferred_exfiltration: List[str] = field(default_factory=list)
    preferred_impact: List[str] = field(default_factory=list)
    preferred_tools: List[str] = field(default_factory=list)

    # Operational Parameters
    max_techniques_per_phase: int = 3  # Maximum techniques to try per tactic
    technique_success_rate: float = 0.7  # Base success probability
    detection_sensitivity: float = 0.5  # 0-1, how much they care about detection
    persistence_priority: float = 0.8  # 0-1, importance of maintaining access
    data_exfiltration_priority: float = 0.6  # 0-1, importance of data theft

    @classmethod
    def from_mitre_data(cls, mitre_client, group_name: str, **kwargs):
        """
        Build persona from MITRE STIX data.

        Args:
            mitre_client: MITREStixClient instance
            group_name: Name of the group (e.g., "APT29")
            **kwargs: Additional persona configuration

        Returns:
            AttackerPersona instance
        """
        group = mitre_client.get_group_by_name(group_name)
        if not group:
            raise ValueError(f"Group '{group_name}' not found in MITRE data")

        techniques = mitre_client.get_techniques_for_group(group['id'])
        software = mitre_client.get_software_for_group(group['id'])

        # Extract MITRE ID from external references
        mitre_id = ""
        for ref in group.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id', '')
                break

        # Extract unique tactics from techniques
        tactics = set()
        for tech in techniques:
            for phase in tech.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.add(phase['phase_name'])

        # Categorize techniques by tactic
        techniques_by_tactic = cls._categorize_techniques_by_tactic(techniques)

        # Create persona with extracted data
        persona = cls(
            stix_id=group['id'],
            mitre_id=mitre_id,
            name=group['name'],
            aliases=group.get('aliases', []),
            description=group.get('description', ''),
            tactics=sorted(list(tactics)),
            techniques=techniques,
            software=software,
            **kwargs
        )

        # Set preferred techniques for each tactic
        persona._set_preferred_techniques(techniques_by_tactic)

        # Extract preferred tools from software
        persona.preferred_tools = [s['name'] for s in software[:5]]  # Top 5 tools

        return persona

    @staticmethod
    def _categorize_techniques_by_tactic(techniques: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize techniques by their tactics."""
        categorized = {}
        for tech in techniques:
            for phase in tech.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactic = phase['phase_name']
                    if tactic not in categorized:
                        categorized[tactic] = []
                    categorized[tactic].append(tech)
        return categorized

    def _set_preferred_techniques(self, techniques_by_tactic: Dict[str, List[Dict]]):
        """Set preferred techniques for each tactic based on available techniques."""
        tactic_to_attr = {
            'initial-access': 'preferred_initial_access',
            'persistence': 'preferred_persistence',
            'privilege-escalation': 'preferred_privilege_escalation',
            'defense-evasion': 'preferred_defense_evasion',
            'credential-access': 'preferred_credential_access',
            'discovery': 'preferred_discovery',
            'lateral-movement': 'preferred_lateral_movement',
            'collection': 'preferred_collection',
            'command-and-control': 'preferred_command_control',
            'exfiltration': 'preferred_exfiltration',
            'impact': 'preferred_impact'
        }

        for tactic, attr_name in tactic_to_attr.items():
            if tactic in techniques_by_tactic:
                # Get technique IDs for this tactic
                technique_ids = [
                    t.get('external_id', t['name'])
                    for t in techniques_by_tactic[tactic][:5]  # Top 5 techniques
                ]
                setattr(self, attr_name, technique_ids)

    def select_technique_for_tactic(self, tactic: str,
                                   exclude: Optional[List[str]] = None) -> Optional[Dict]:
        """
        Select a technique for given tactic from persona's arsenal.

        Args:
            tactic: MITRE tactic name (e.g., "initial-access")
            exclude: List of technique IDs to exclude

        Returns:
            Selected technique dict or None if no techniques available
        """
        exclude = exclude or []

        matching = []
        for tech in self.techniques:
            # Check if technique is for this tactic
            for phase in tech.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack' and \
                   phase.get('phase_name') == tactic:
                    # Check if not excluded
                    if tech.get('external_id') not in exclude:
                        matching.append(tech)
                    break

        if not matching:
            logger.warning(f"No techniques available for tactic: {tactic}")
            return None

        # Select based on sophistication level
        if self.sophistication_level == SophisticationLevel.ADVANCED:
            # Advanced actors use diverse techniques
            return random.choice(matching)
        else:
            # Less sophisticated actors use common techniques
            return matching[0]  # Use first (most common) technique

    def get_attack_chain(self, scenario: str = "full_chain") -> List[Dict]:
        """
        Generate an attack chain based on persona's TTPs.

        Args:
            scenario: Attack scenario type

        Returns:
            Ordered list of attack phases with techniques
        """
        chain = []

        if scenario == "full_chain":
            # Standard kill chain progression
            tactic_order = [
                'reconnaissance',
                'initial-access',
                'execution',
                'persistence',
                'privilege-escalation',
                'defense-evasion',
                'credential-access',
                'discovery',
                'lateral-movement',
                'collection',
                'command-and-control',
                'exfiltration',
                'impact'
            ]
        elif scenario == "ransomware":
            # Ransomware-focused chain
            tactic_order = [
                'initial-access',
                'execution',
                'privilege-escalation',
                'defense-evasion',
                'discovery',
                'lateral-movement',
                'impact'
            ]
        elif scenario == "data_theft":
            # Data exfiltration focused
            tactic_order = [
                'initial-access',
                'execution',
                'persistence',
                'credential-access',
                'discovery',
                'collection',
                'exfiltration'
            ]
        else:
            # Default to available tactics
            tactic_order = self.tactics

        # Build chain from available techniques
        for tactic in tactic_order:
            if tactic not in self.tactics:
                continue

            technique = self.select_technique_for_tactic(tactic)
            if technique:
                chain.append({
                    'tactic': tactic,
                    'technique_id': technique.get('external_id', ''),
                    'technique_name': technique.get('name', ''),
                    'description': technique.get('description', '')[:200] + '...'
                })

        return chain

    def should_use_stealth_technique(self) -> bool:
        """Determine if stealth techniques should be used based on persona preferences."""
        if self.stealth_preference == StealthLevel.STEALTHY:
            return random.random() < 0.9
        elif self.stealth_preference == StealthLevel.BALANCED:
            return random.random() < 0.5
        else:  # NOISY
            return random.random() < 0.1

    def get_dwell_time(self) -> int:
        """Get expected dwell time in days based on persona characteristics."""
        base_dwell = {
            SophisticationLevel.LOW: 30,
            SophisticationLevel.MEDIUM: 90,
            SophisticationLevel.HIGH: 180,
            SophisticationLevel.ADVANCED: 365
        }

        dwell = base_dwell.get(self.sophistication_level, 90)

        # Adjust based on stealth
        if self.stealth_preference == StealthLevel.STEALTHY:
            dwell *= 1.5
        elif self.stealth_preference == StealthLevel.NOISY:
            dwell *= 0.5

        return int(dwell)

    def to_dict(self) -> Dict:
        """Serialize persona for API/DB storage."""
        return {
            'stix_id': self.stix_id,
            'mitre_id': self.mitre_id,
            'name': self.name,
            'aliases': self.aliases,
            'description': self.description[:500] if self.description else '',
            'tactics': self.tactics,
            'technique_count': len(self.techniques),
            'technique_ids': [t.get('external_id', '') for t in self.techniques[:10]],
            'software_count': len(self.software),
            'software_names': [s.get('name', '') for s in self.software[:5]],
            'sophistication': self.sophistication_level.value,
            'stealth': self.stealth_preference.value,
            'attack_speed': self.attack_speed.value,
            'target_industries': self.target_industries,
            'target_regions': self.target_regions,
            'motivations': self.motivations,
            'expected_dwell_time': self.get_dwell_time()
        }

    def to_json_summary(self) -> Dict:
        """Get a summary representation for logging/display."""
        return {
            'name': self.name,
            'mitre_id': self.mitre_id,
            'sophistication': self.sophistication_level.value,
            'techniques': len(self.techniques),
            'tools': len(self.software),
            'tactics': self.tactics
        }

    def __repr__(self):
        return (f"AttackerPersona(name='{self.name}', mitre_id='{self.mitre_id}', "
                f"techniques={len(self.techniques)}, sophistication={self.sophistication_level.value})")