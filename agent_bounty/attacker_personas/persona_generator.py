"""
Automated Persona Generation System
Intelligently generates behavioral characteristics for all MITRE groups
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from collections import Counter

from agent_bounty.attacker_personas.persona import (
    AttackerPersona, SophisticationLevel, StealthLevel, AttackSpeed
)
from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient

logger = logging.getLogger(__name__)


class PersonaGenerator:
    """
    Automatically generates sophisticated persona configurations for all MITRE groups.
    Uses heuristics, pattern analysis, and intelligence research to infer behavioral characteristics.
    """

    def __init__(self, mitre_client: MITREStixClient):
        self.mitre_client = mitre_client
        self._industry_keywords = self._load_industry_keywords()
        self._region_keywords = self._load_region_keywords()
        self._sophistication_indicators = self._load_sophistication_indicators()

    def generate_all_personas(self) -> Dict[str, Dict]:
        """
        Generate persona configurations for all MITRE groups.

        Returns:
            Dictionary mapping group names to persona configurations
        """
        all_groups = self.mitre_client.get_all_groups()
        generated_configs = {}

        logger.info(f"Generating personas for {len(all_groups)} MITRE groups...")

        for group in all_groups:
            try:
                config = self.generate_persona_config(group)
                generated_configs[group['name']] = config
                logger.debug(f"Generated config for {group['name']}")
            except Exception as e:
                logger.error(f"Failed to generate config for {group.get('name', 'Unknown')}: {e}")
                continue

        logger.info(f"Successfully generated {len(generated_configs)} persona configurations")
        return generated_configs

    def generate_persona_config(self, group: Dict) -> Dict:
        """
        Generate persona configuration for a single group.

        Args:
            group: MITRE group object

        Returns:
            Persona configuration dictionary
        """
        group_name = group.get('name', '')
        description = group.get('description', '')
        aliases = group.get('aliases', [])

        # Get techniques and software
        techniques = self.mitre_client.get_techniques_for_group(group['id'])
        software = self.mitre_client.get_software_for_group(group['id'])

        # Analyze group characteristics
        sophistication = self._infer_sophistication(group, techniques, software)
        stealth = self._infer_stealth_preference(group, techniques)
        attack_speed = self._infer_attack_speed(group, techniques)
        target_industries = self._infer_target_industries(description, aliases)
        target_regions = self._infer_target_regions(description, aliases)
        motivations = self._infer_motivations(group, techniques, description)

        # Generate operational parameters
        detection_sensitivity = self._calculate_detection_sensitivity(stealth, sophistication)
        persistence_priority = self._calculate_persistence_priority(techniques)
        data_exfiltration_priority = self._calculate_exfiltration_priority(techniques, motivations)

        config = {
            'sophistication_level': sophistication,
            'stealth_preference': stealth,
            'attack_speed': attack_speed,
            'target_industries': target_industries,
            'target_regions': target_regions,
            'motivations': motivations,
            'detection_sensitivity': detection_sensitivity,
            'persistence_priority': persistence_priority,
            'data_exfiltration_priority': data_exfiltration_priority,
            'max_techniques_per_phase': self._calculate_max_techniques(sophistication),
            'description_override': self._generate_description(group, motivations, target_industries),
            'preferred_tools': [s.get('name', '') for s in software[:5]],
            'technique_success_rate': self._calculate_success_rate(sophistication),
            'generation_method': 'automated',
            'confidence_score': self._calculate_confidence_score(group, techniques, software)
        }

        return config

    def _infer_sophistication(self, group: Dict, techniques: List[Dict], software: List[Dict]) -> SophisticationLevel:
        """Infer sophistication level based on various indicators."""
        score = 0

        # Technique count (more techniques = higher sophistication)
        if len(techniques) > 80:
            score += 3
        elif len(techniques) > 50:
            score += 2
        elif len(techniques) > 20:
            score += 1

        # Software count (more tools = higher sophistication)
        if len(software) > 20:
            score += 2
        elif len(software) > 10:
            score += 1

        # Name-based indicators
        name = group.get('name', '').lower()
        description = group.get('description', '').lower()
        aliases = ' '.join(group.get('aliases', [])).lower()
        combined_text = f"{name} {description} {aliases}"

        # Nation-state indicators
        nation_state_indicators = [
            'apt', 'government', 'state-sponsored', 'nation', 'military',
            'intelligence', 'ministry', 'bureau', 'unit 61398', 'pla'
        ]

        if any(indicator in combined_text for indicator in nation_state_indicators):
            score += 2

        # Advanced technique indicators
        advanced_techniques = ['T1055', 'T1027', 'T1140', 'T1134', 'T1574']  # Process injection, obfuscation, etc.
        if any(tech.get('external_id', '') in advanced_techniques for tech in techniques):
            score += 1

        # Custom malware indicators
        if any('custom' in s.get('name', '').lower() for s in software):
            score += 1

        # Map score to sophistication level
        if score >= 6:
            return SophisticationLevel.ADVANCED
        elif score >= 4:
            return SophisticationLevel.HIGH
        elif score >= 2:
            return SophisticationLevel.MEDIUM
        else:
            return SophisticationLevel.LOW

    def _infer_stealth_preference(self, group: Dict, techniques: List[Dict]) -> StealthLevel:
        """Infer stealth preference based on techniques and description."""
        stealth_score = 0

        # Stealthy techniques
        stealthy_techniques = ['T1027', 'T1140', 'T1036', 'T1112', 'T1564']  # Obfuscation, masquerading, etc.
        noisy_techniques = ['T1486', 'T1490', 'T1489', 'T1561']  # Ransomware, wiper malware, etc.

        stealth_count = sum(1 for tech in techniques if tech.get('external_id', '') in stealthy_techniques)
        noisy_count = sum(1 for tech in techniques if tech.get('external_id', '') in noisy_techniques)

        if stealth_count > noisy_count * 2:
            stealth_score += 2
        elif stealth_count > noisy_count:
            stealth_score += 1
        elif noisy_count > stealth_count * 2:
            stealth_score -= 2

        # Description analysis
        description = group.get('description', '').lower()
        if any(word in description for word in ['covert', 'stealth', 'undetected', 'persistent']):
            stealth_score += 1
        if any(word in description for word in ['destructive', 'ransomware', 'wiper', 'disruptive']):
            stealth_score -= 1

        if stealth_score >= 2:
            return StealthLevel.STEALTHY
        elif stealth_score <= -1:
            return StealthLevel.NOISY
        else:
            return StealthLevel.BALANCED

    def _infer_attack_speed(self, group: Dict, techniques: List[Dict]) -> AttackSpeed:
        """Infer attack speed based on operational patterns."""
        # Check for automation and rapid deployment techniques
        fast_techniques = ['T1059', 'T1569', 'T1053']  # Scripting, service execution, scheduled tasks
        slow_techniques = ['T1547', 'T1176', 'T1137']  # Boot/logon persistence, browser extensions

        fast_count = sum(1 for tech in techniques if tech.get('external_id', '') in fast_techniques)
        slow_count = sum(1 for tech in techniques if tech.get('external_id', '') in slow_techniques)

        # Description indicators
        description = group.get('description', '').lower()
        if any(word in description for word in ['rapid', 'automated', 'scripted', 'fast']):
            return AttackSpeed.FAST
        elif any(word in description for word in ['patient', 'long-term', 'persistent', 'dormant']):
            return AttackSpeed.SLOW

        # Default based on technique ratio
        if fast_count > slow_count * 2:
            return AttackSpeed.FAST
        elif slow_count > fast_count:
            return AttackSpeed.SLOW
        else:
            return AttackSpeed.MODERATE

    def _infer_target_industries(self, description: str, aliases: List[str]) -> List[str]:
        """Infer target industries from description and aliases."""
        combined_text = f"{description} {' '.join(aliases)}".lower()

        detected_industries = []
        for industry, keywords in self._industry_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                detected_industries.append(industry)

        # Default to general if no specific industries detected
        return detected_industries if detected_industries else ['Technology', 'Government']

    def _infer_target_regions(self, description: str, aliases: List[str]) -> List[str]:
        """Infer target regions from description and aliases."""
        combined_text = f"{description} {' '.join(aliases)}".lower()

        detected_regions = []
        for region, keywords in self._region_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                detected_regions.append(region)

        # Default to global if no specific regions detected
        return detected_regions if detected_regions else ['Global']

    def _infer_motivations(self, group: Dict, techniques: List[Dict], description: str) -> List[str]:
        """Infer attack motivations."""
        motivations = []

        # Financial indicators
        financial_techniques = ['T1005', 'T1041', 'T1486']  # Data collection, exfiltration, ransomware
        if any(tech.get('external_id', '') in financial_techniques for tech in techniques):
            motivations.append('financial')

        # Espionage indicators
        espionage_techniques = ['T1005', 'T1041', 'T1056', 'T1113']  # Data collection, keylogging, screenshots
        if any(tech.get('external_id', '') in espionage_techniques for tech in techniques):
            motivations.append('espionage')

        # Destructive indicators
        destructive_techniques = ['T1486', 'T1490', 'T1561']  # Ransomware, inhibit recovery, disk wipe
        if any(tech.get('external_id', '') in destructive_techniques for tech in techniques):
            motivations.append('destruction')

        # Description analysis
        desc_lower = description.lower()
        if any(word in desc_lower for word in ['financial', 'money', 'bank', 'payment']):
            motivations.append('financial')
        if any(word in desc_lower for word in ['espionage', 'intelligence', 'surveillance']):
            motivations.append('espionage')
        if any(word in desc_lower for word in ['disrupt', 'destroy', 'damage']):
            motivations.append('disruption')

        return list(set(motivations)) if motivations else ['espionage']

    def _calculate_detection_sensitivity(self, stealth: StealthLevel, sophistication: SophisticationLevel) -> float:
        """Calculate how much the group cares about detection."""
        base_sensitivity = 0.5

        if stealth == StealthLevel.STEALTHY:
            base_sensitivity += 0.3
        elif stealth == StealthLevel.NOISY:
            base_sensitivity -= 0.3

        if sophistication == SophisticationLevel.ADVANCED:
            base_sensitivity += 0.2
        elif sophistication == SophisticationLevel.LOW:
            base_sensitivity -= 0.2

        return max(0.1, min(0.95, base_sensitivity))

    def _calculate_persistence_priority(self, techniques: List[Dict]) -> float:
        """Calculate persistence priority based on techniques."""
        persistence_techniques = ['T1547', 'T1053', 'T1543', 'T1574']
        persistence_count = sum(1 for tech in techniques if tech.get('external_id', '') in persistence_techniques)

        # Normalize based on total techniques
        if len(techniques) > 0:
            persistence_ratio = persistence_count / len(techniques)
            return min(0.95, 0.5 + persistence_ratio * 2)
        return 0.7

    def _calculate_exfiltration_priority(self, techniques: List[Dict], motivations: List[str]) -> float:
        """Calculate data exfiltration priority."""
        exfiltration_techniques = ['T1041', 'T1048', 'T1052', 'T1567']
        exfil_count = sum(1 for tech in techniques if tech.get('external_id', '') in exfiltration_techniques)

        base_priority = 0.5
        if 'financial' in motivations or 'espionage' in motivations:
            base_priority += 0.3
        if 'destruction' in motivations:
            base_priority -= 0.2

        if len(techniques) > 0:
            exfil_ratio = exfil_count / len(techniques)
            base_priority += exfil_ratio * 2

        return max(0.1, min(0.95, base_priority))

    def _calculate_max_techniques(self, sophistication: SophisticationLevel) -> int:
        """Calculate maximum techniques per phase."""
        if sophistication == SophisticationLevel.ADVANCED:
            return 7
        elif sophistication == SophisticationLevel.HIGH:
            return 5
        elif sophistication == SophisticationLevel.MEDIUM:
            return 4
        else:
            return 3

    def _calculate_success_rate(self, sophistication: SophisticationLevel) -> float:
        """Calculate base technique success rate."""
        rates = {
            SophisticationLevel.ADVANCED: 0.85,
            SophisticationLevel.HIGH: 0.75,
            SophisticationLevel.MEDIUM: 0.65,
            SophisticationLevel.LOW: 0.55
        }
        return rates.get(sophistication, 0.7)

    def _generate_description(self, group: Dict, motivations: List[str], industries: List[str]) -> str:
        """Generate a concise description for the group."""
        name = group.get('name', 'Unknown')
        original_desc = group.get('description', '')

        # Extract key info from original description
        motivation_str = ', '.join(motivations).replace('_', ' ')
        industry_str = ', '.join(industries[:3])  # Limit to top 3 industries

        if len(original_desc) > 200:
            # Use first sentence or first 150 chars
            sentences = original_desc.split('. ')
            if sentences:
                base_desc = sentences[0]
            else:
                base_desc = original_desc[:150] + "..."
        else:
            base_desc = original_desc

        if not base_desc:
            base_desc = f"Threat group with {motivation_str} motivations targeting {industry_str} sectors"

        return base_desc

    def _calculate_confidence_score(self, group: Dict, techniques: List[Dict], software: List[Dict]) -> float:
        """Calculate confidence in the generated configuration."""
        score = 0.5  # Base confidence

        # More data = higher confidence
        if len(techniques) > 50:
            score += 0.2
        elif len(techniques) > 20:
            score += 0.1
        elif len(techniques) < 5:
            score -= 0.2

        if len(software) > 10:
            score += 0.1
        elif len(software) < 2:
            score -= 0.1

        # Description quality
        description = group.get('description', '')
        if len(description) > 500:
            score += 0.1
        elif len(description) < 100:
            score -= 0.1

        # Aliases provide additional context
        if len(group.get('aliases', [])) > 2:
            score += 0.05

        return max(0.1, min(0.95, score))

    def _load_industry_keywords(self) -> Dict[str, List[str]]:
        """Load industry keyword mappings."""
        return {
            'Government': ['government', 'military', 'defense', 'embassy', 'diplomatic', 'ministry', 'agency'],
            'Financial': ['bank', 'financial', 'finance', 'payment', 'credit', 'monetary', 'treasury'],
            'Technology': ['technology', 'software', 'tech', 'IT', 'computer', 'semiconductor', 'cloud'],
            'Healthcare': ['healthcare', 'hospital', 'medical', 'pharmaceutical', 'health', 'patient'],
            'Energy': ['energy', 'oil', 'gas', 'electric', 'power', 'utility', 'petroleum', 'nuclear'],
            'Telecommunications': ['telecom', 'telecommunication', 'mobile', 'cellular', 'phone', 'network'],
            'Manufacturing': ['manufacturing', 'industrial', 'factory', 'production', 'automotive'],
            'Education': ['education', 'university', 'school', 'academic', 'research', 'student'],
            'Media': ['media', 'journalism', 'news', 'broadcast', 'television', 'radio', 'press'],
            'Retail': ['retail', 'shopping', 'store', 'commerce', 'sales', 'consumer'],
            'Aviation': ['aviation', 'airline', 'aircraft', 'aerospace', 'flight'],
            'Maritime': ['maritime', 'shipping', 'port', 'naval', 'ocean'],
            'Critical Infrastructure': ['infrastructure', 'critical', 'transportation', 'water', 'dam']
        }

    def _load_region_keywords(self) -> Dict[str, List[str]]:
        """Load regional keyword mappings."""
        return {
            'North America': ['united states', 'america', 'us', 'canada', 'mexico', 'north america'],
            'Europe': ['europe', 'european', 'eu', 'uk', 'britain', 'germany', 'france', 'nato'],
            'Asia Pacific': ['asia', 'china', 'japan', 'korea', 'singapore', 'australia', 'pacific'],
            'Middle East': ['middle east', 'israel', 'iran', 'saudi', 'uae', 'turkey', 'gulf'],
            'Africa': ['africa', 'south africa', 'nigeria', 'egypt'],
            'South America': ['south america', 'brazil', 'argentina', 'colombia'],
            'Russia/CIS': ['russia', 'russian', 'soviet', 'ukraine', 'belarus', 'cis'],
            'Global': ['global', 'worldwide', 'international', 'multinational']
        }

    def _load_sophistication_indicators(self) -> Dict[str, List[str]]:
        """Load sophistication indicator mappings."""
        return {
            'nation_state': ['apt', 'government', 'state-sponsored', 'military', 'intelligence'],
            'criminal': ['fin', 'gang', 'criminal', 'cybercrime', 'crimeware'],
            'hacktivist': ['anonymous', 'activist', 'hacktivist', 'political'],
            'advanced': ['custom', 'zero-day', 'sophisticated', 'advanced', 'complex']
        }