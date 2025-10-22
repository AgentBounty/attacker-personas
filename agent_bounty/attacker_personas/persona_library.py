"""
Pre-configured Attacker Persona Library
Defines real APT groups with their characteristics and TTPs
"""

import logging
from typing import Dict, List, Optional
from agent_bounty.attacker_personas.persona import (
    AttackerPersona, SophisticationLevel, StealthLevel, AttackSpeed
)
from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient
from agent_bounty.attacker_personas.persona_generator import PersonaGenerator

logger = logging.getLogger(__name__)


# Pre-configured persona metadata for real APT groups
PERSONA_CONFIGS = {
    'APT29': {
        'sophistication_level': SophisticationLevel.ADVANCED,
        'stealth_preference': StealthLevel.STEALTHY,
        'attack_speed': AttackSpeed.SLOW,
        'target_industries': ['Government', 'Technology', 'Energy', 'Healthcare', 'Think Tanks'],
        'target_regions': ['North America', 'Europe', 'Asia'],
        'motivations': ['espionage', 'intelligence_gathering'],
        'preferred_tools': ['PowerShell Empire', 'Cobalt Strike', 'Custom Malware'],
        'description_override': 'Russian state-sponsored group (SVR) known for sophisticated, stealthy operations',
        'detection_sensitivity': 0.9,  # Very concerned about detection
        'persistence_priority': 0.95,  # Very high persistence priority
        'data_exfiltration_priority': 0.9,
        'max_techniques_per_phase': 5
    },
    'APT28': {
        'sophistication_level': SophisticationLevel.ADVANCED,
        'stealth_preference': StealthLevel.BALANCED,
        'attack_speed': AttackSpeed.MODERATE,
        'target_industries': ['Government', 'Defense', 'Aerospace', 'Media', 'Think Tanks'],
        'target_regions': ['Europe', 'North America', 'Middle East', 'Asia'],
        'motivations': ['espionage', 'information_warfare', 'disruption'],
        'preferred_tools': ['Sofacy', 'X-Agent', 'X-Tunnel', 'Mimikatz'],
        'description_override': 'Russian military intelligence (GRU) with aggressive operational style',
        'detection_sensitivity': 0.6,
        'persistence_priority': 0.8,
        'data_exfiltration_priority': 0.7,
        'max_techniques_per_phase': 4
    },
    'Lazarus Group': {
        'sophistication_level': SophisticationLevel.ADVANCED,
        'stealth_preference': StealthLevel.NOISY,
        'attack_speed': AttackSpeed.FAST,
        'target_industries': ['Financial', 'Cryptocurrency', 'Defense', 'Technology', 'Media'],
        'target_regions': ['Global'],
        'motivations': ['financial', 'disruption', 'espionage', 'destruction'],
        'preferred_tools': ['Custom Malware', 'DTrack', 'Bankshot', 'WannaCry'],
        'description_override': 'North Korean state-sponsored group known for destructive attacks and financial theft',
        'detection_sensitivity': 0.3,  # Less concerned about detection
        'persistence_priority': 0.7,
        'data_exfiltration_priority': 0.8,
        'max_techniques_per_phase': 6
    },
    'FIN7': {
        'sophistication_level': SophisticationLevel.HIGH,
        'stealth_preference': StealthLevel.STEALTHY,
        'attack_speed': AttackSpeed.MODERATE,
        'target_industries': ['Retail', 'Hospitality', 'Restaurant', 'Financial Services'],
        'target_regions': ['North America', 'Europe', 'Asia'],
        'motivations': ['financial'],
        'preferred_tools': ['Carbanak', 'Cobalt Strike', 'PowerShell', 'Mimikatz'],
        'description_override': 'Financially motivated cybercriminal group targeting payment card data',
        'detection_sensitivity': 0.8,
        'persistence_priority': 0.85,
        'data_exfiltration_priority': 0.95,  # Very high - focused on data theft
        'max_techniques_per_phase': 4
    },
    'APT1': {
        'sophistication_level': SophisticationLevel.HIGH,
        'stealth_preference': StealthLevel.BALANCED,
        'attack_speed': AttackSpeed.MODERATE,
        'target_industries': ['Technology', 'Financial', 'Manufacturing', 'Energy', 'Healthcare'],
        'target_regions': ['North America', 'Europe', 'Asia Pacific'],
        'motivations': ['espionage', 'intellectual_property_theft'],
        'preferred_tools': ['WEBC2', 'BISCUIT', 'SEASALT', 'Custom Tools'],
        'description_override': 'Chinese military unit focused on intellectual property theft',
        'detection_sensitivity': 0.5,
        'persistence_priority': 0.9,
        'data_exfiltration_priority': 0.85,
        'max_techniques_per_phase': 3
    },
    'Carbanak': {
        'sophistication_level': SophisticationLevel.HIGH,
        'stealth_preference': StealthLevel.STEALTHY,
        'attack_speed': AttackSpeed.SLOW,
        'target_industries': ['Financial', 'Hospitality', 'Retail'],
        'target_regions': ['Global'],
        'motivations': ['financial'],
        'preferred_tools': ['Carbanak Malware', 'Cobalt Strike', 'Mimikatz', 'Metasploit'],
        'description_override': 'Cybercriminal group specializing in financial institution theft',
        'detection_sensitivity': 0.85,
        'persistence_priority': 0.8,
        'data_exfiltration_priority': 0.9,
        'max_techniques_per_phase': 3
    },
    'APT33': {
        'sophistication_level': SophisticationLevel.HIGH,
        'stealth_preference': StealthLevel.BALANCED,
        'attack_speed': AttackSpeed.MODERATE,
        'target_industries': ['Aviation', 'Energy', 'Government', 'Defense'],
        'target_regions': ['Middle East', 'North America', 'Europe'],
        'motivations': ['espionage', 'disruption'],
        'preferred_tools': ['DROPSHOT', 'SHAPESHIFT', 'TURNEDUP', 'Custom Malware'],
        'description_override': 'Iranian group targeting aviation and energy sectors',
        'detection_sensitivity': 0.6,
        'persistence_priority': 0.75,
        'data_exfiltration_priority': 0.7,
        'max_techniques_per_phase': 4
    },
    'Equation': {
        'sophistication_level': SophisticationLevel.ADVANCED,
        'stealth_preference': StealthLevel.STEALTHY,
        'attack_speed': AttackSpeed.SLOW,
        'target_industries': ['Government', 'Technology', 'Telecommunications', 'Defense', 'Research'],
        'target_regions': ['Global'],
        'motivations': ['espionage', 'intelligence_gathering'],
        'preferred_tools': ['EQUATIONDRUG', 'GRAYFISH', 'FANNY', 'Custom Implants'],
        'description_override': 'Highly sophisticated group with advanced persistent capabilities',
        'detection_sensitivity': 0.95,
        'persistence_priority': 0.98,
        'data_exfiltration_priority': 0.85,
        'max_techniques_per_phase': 7
    },
    'DarkHydrus': {
        'sophistication_level': SophisticationLevel.MEDIUM,
        'stealth_preference': StealthLevel.BALANCED,
        'attack_speed': AttackSpeed.MODERATE,
        'target_industries': ['Government', 'Critical Infrastructure', 'Energy'],
        'target_regions': ['Middle East'],
        'motivations': ['espionage'],
        'preferred_tools': ['RogueRobin', 'PowerShell', 'Custom Scripts'],
        'description_override': 'Middle Eastern group targeting government entities',
        'detection_sensitivity': 0.5,
        'persistence_priority': 0.7,
        'data_exfiltration_priority': 0.75,
        'max_techniques_per_phase': 3
    },
    'Sandworm Team': {
        'sophistication_level': SophisticationLevel.ADVANCED,
        'stealth_preference': StealthLevel.NOISY,
        'attack_speed': AttackSpeed.FAST,
        'target_industries': ['Energy', 'Critical Infrastructure', 'Government', 'Media'],
        'target_regions': ['Europe', 'North America', 'Asia'],
        'motivations': ['disruption', 'destruction', 'espionage'],
        'preferred_tools': ['NotPetya', 'BlackEnergy', 'Industroyer', 'Custom Malware'],
        'description_override': 'Russian group known for destructive attacks on critical infrastructure',
        'detection_sensitivity': 0.2,  # Often doesn't care about detection
        'persistence_priority': 0.6,
        'data_exfiltration_priority': 0.4,  # More focused on disruption
        'max_techniques_per_phase': 5
    }
}


class PersonaLibrary:
    """
    Manager for pre-configured and custom attacker personas.

    Provides access to real-world APT groups with accurate MITRE ATT&CK
    techniques and behavioral characteristics.
    """

    def __init__(self, mitre_client: Optional[MITREStixClient] = None,
                 cache_personas: bool = True,
                 auto_generate: bool = True):
        """
        Initialize persona library.

        Args:
            mitre_client: MITRE STIX client instance (creates one if not provided)
            cache_personas: Whether to cache loaded personas
            auto_generate: Whether to auto-generate personas for unknown groups
        """
        self.mitre_client = mitre_client or MITREStixClient()
        self._personas_cache = {} if cache_personas else None
        self._custom_personas = {}
        self._auto_generate = auto_generate
        self._generator = PersonaGenerator(self.mitre_client) if auto_generate else None

    def get_persona(self, name: str) -> AttackerPersona:
        """
        Get or create persona from MITRE data + pre-configured settings.

        Args:
            name: Persona name (e.g., "APT29", "Lazarus Group")

        Returns:
            AttackerPersona instance

        Raises:
            ValueError: If persona name is not found
        """
        # Check cache first
        if self._personas_cache is not None and name in self._personas_cache:
            logger.debug(f"Returning cached persona: {name}")
            return self._personas_cache[name]

        # Check custom personas
        if name in self._custom_personas:
            return self._custom_personas[name]

        # Check pre-configured personas
        if name not in PERSONA_CONFIGS:
            # Try to find in MITRE data directly
            group = self.mitre_client.get_group_by_name(name)
            if not group:
                available = self.list_available_personas()
                raise ValueError(
                    f"Unknown persona: '{name}'. Available personas: {', '.join(available)}"
                )

            # Use auto-generation if enabled, otherwise basic persona
            if self._auto_generate and self._generator:
                logger.info(f"Auto-generating sophisticated persona: {name}")
                config = self._generator.generate_persona_config(group)

                # Remove description_override to handle separately
                description_override = config.pop('description_override', None)

                persona = AttackerPersona.from_mitre_data(
                    self.mitre_client,
                    name,
                    **{k: v for k, v in config.items() if k not in ['generation_method', 'confidence_score']}
                )

                # Override description if provided
                if description_override:
                    persona.description = description_override
            else:
                # Create basic persona from MITRE data only
                logger.info(f"Creating basic persona from MITRE data: {name}")
                persona = AttackerPersona.from_mitre_data(self.mitre_client, name)
        else:
            # Create persona with pre-configured settings
            config = PERSONA_CONFIGS[name].copy()
            logger.info(f"Loading pre-configured persona: {name}")

            # Remove description_override to handle separately
            description_override = config.pop('description_override', None)

            persona = AttackerPersona.from_mitre_data(
                self.mitre_client,
                name,
                **config
            )

            # Override description if provided
            if description_override:
                persona.description = description_override

        # Cache if enabled
        if self._personas_cache is not None:
            self._personas_cache[name] = persona

        logger.info(f"Loaded persona: {persona.name} with {len(persona.techniques)} techniques")
        return persona

    def create_custom_persona(self, name: str, base_persona: Optional[str] = None,
                            **attributes) -> AttackerPersona:
        """
        Create a custom persona with specified attributes.

        Args:
            name: Custom persona name
            base_persona: Optional base persona to inherit from
            **attributes: Persona attributes to set/override

        Returns:
            Custom AttackerPersona instance
        """
        if base_persona:
            # Start from existing persona
            base = self.get_persona(base_persona)
            persona = AttackerPersona(
                stix_id=f"custom--{name.lower().replace(' ', '-')}",
                mitre_id=f"C{len(self._custom_personas):04d}",
                name=name,
                aliases=base.aliases,
                description=attributes.get('description', base.description),
                tactics=base.tactics,
                techniques=base.techniques,
                software=base.software,
                sophistication_level=attributes.get('sophistication_level', base.sophistication_level),
                stealth_preference=attributes.get('stealth_preference', base.stealth_preference),
                attack_speed=attributes.get('attack_speed', base.attack_speed),
                target_industries=attributes.get('target_industries', base.target_industries),
                target_regions=attributes.get('target_regions', base.target_regions),
                motivations=attributes.get('motivations', base.motivations),
                preferred_tools=attributes.get('preferred_tools', base.preferred_tools)
            )
        else:
            # Create from scratch
            persona = AttackerPersona(
                stix_id=f"custom--{name.lower().replace(' ', '-')}",
                mitre_id=f"C{len(self._custom_personas):04d}",
                name=name,
                **attributes
            )

        self._custom_personas[name] = persona
        logger.info(f"Created custom persona: {name}")
        return persona

    def list_available_personas(self) -> List[str]:
        """List all available pre-configured personas."""
        return sorted(list(PERSONA_CONFIGS.keys()))

    def list_all_mitre_groups(self) -> List[Dict]:
        """
        List all groups available in MITRE ATT&CK data.

        Returns:
            List of group summaries with name and MITRE ID
        """
        groups = self.mitre_client.get_all_groups()
        return [
            {
                'name': g.get('name'),
                'mitre_id': g.get('mitre_id', ''),
                'aliases': g.get('aliases', [])
            }
            for g in groups
        ]

    def get_personas_by_industry(self, industry: str) -> List[str]:
        """
        Get personas that target a specific industry.

        Args:
            industry: Industry name

        Returns:
            List of persona names
        """
        matching = []
        for name, config in PERSONA_CONFIGS.items():
            industries = config.get('target_industries', [])
            if any(industry.lower() in ind.lower() for ind in industries):
                matching.append(name)
        return matching

    def get_personas_by_sophistication(self,
                                      level: SophisticationLevel) -> List[str]:
        """
        Get personas with specific sophistication level.

        Args:
            level: Sophistication level

        Returns:
            List of persona names
        """
        matching = []
        for name, config in PERSONA_CONFIGS.items():
            if config.get('sophistication_level') == level:
                matching.append(name)
        return matching

    def get_personas_by_motivation(self, motivation: str) -> List[str]:
        """
        Get personas with specific motivation.

        Args:
            motivation: Motivation type (e.g., 'financial', 'espionage')

        Returns:
            List of persona names
        """
        matching = []
        for name, config in PERSONA_CONFIGS.items():
            motivations = config.get('motivations', [])
            if motivation.lower() in [m.lower() for m in motivations]:
                matching.append(name)
        return matching

    def compare_personas(self, persona1: str, persona2: str) -> Dict:
        """
        Compare two personas' capabilities and characteristics.

        Args:
            persona1: First persona name
            persona2: Second persona name

        Returns:
            Comparison dictionary
        """
        p1 = self.get_persona(persona1)
        p2 = self.get_persona(persona2)

        # Find common and unique techniques
        p1_tech_ids = set(t.get('external_id', '') for t in p1.techniques)
        p2_tech_ids = set(t.get('external_id', '') for t in p2.techniques)

        return {
            'persona1': {
                'name': p1.name,
                'sophistication': p1.sophistication_level.value,
                'technique_count': len(p1.techniques),
                'unique_techniques': len(p1_tech_ids - p2_tech_ids)
            },
            'persona2': {
                'name': p2.name,
                'sophistication': p2.sophistication_level.value,
                'technique_count': len(p2.techniques),
                'unique_techniques': len(p2_tech_ids - p1_tech_ids)
            },
            'common_techniques': len(p1_tech_ids & p2_tech_ids),
            'common_tactics': list(set(p1.tactics) & set(p2.tactics))
        }

    def generate_all_personas(self, save_to_file: bool = False) -> Dict[str, Dict]:
        """
        Generate configurations for all 181 MITRE groups.

        Args:
            save_to_file: Whether to save generated configs to file

        Returns:
            Dictionary mapping group names to configurations
        """
        if not self._auto_generate or not self._generator:
            raise RuntimeError("Auto-generation is disabled. Enable with auto_generate=True")

        logger.info("Generating configurations for all MITRE groups...")
        all_configs = self._generator.generate_all_personas()

        if save_to_file:
            from agent_bounty.attacker_personas.bulk_generator import BulkPersonaGenerator
            bulk_gen = BulkPersonaGenerator(self.mitre_client)
            bulk_gen._save_generated_personas(all_configs, "all_personas_generated.json")

        return all_configs

    def get_auto_generated_stats(self) -> Dict:
        """
        Get statistics about auto-generated personas vs pre-configured.

        Returns:
            Statistics dictionary
        """
        all_groups = self.mitre_client.get_all_groups()
        total_groups = len(all_groups)
        pre_configured = len(PERSONA_CONFIGS)
        auto_generated = total_groups - pre_configured

        return {
            'total_mitre_groups': total_groups,
            'pre_configured_personas': pre_configured,
            'auto_generated_personas': auto_generated,
            'coverage_percentage': (pre_configured / total_groups) * 100,
            'auto_generation_enabled': self._auto_generate,
            'sample_auto_generated': [
                group['name'] for group in all_groups
                if group['name'] not in PERSONA_CONFIGS
            ][:10]
        }

    def clear_cache(self):
        """Clear the persona cache."""
        if self._personas_cache is not None:
            self._personas_cache.clear()
            logger.info("Persona cache cleared")