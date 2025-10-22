"""
Bulk Persona Generation and Management Tools
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient
from agent_bounty.attacker_personas.persona_generator import PersonaGenerator
from agent_bounty.attacker_personas.persona_library import PERSONA_CONFIGS

logger = logging.getLogger(__name__)


class BulkPersonaGenerator:
    """
    Tool for generating and managing all 181 MITRE personas at scale.
    """

    def __init__(self, mitre_client: Optional[MITREStixClient] = None,
                 output_dir: str = "generated_personas"):
        self.mitre_client = mitre_client or MITREStixClient()
        self.generator = PersonaGenerator(self.mitre_client)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_all_missing_personas(self, min_confidence: float = 0.3) -> Dict[str, Dict]:
        """
        Generate personas for all MITRE groups not in PERSONA_CONFIGS.

        Args:
            min_confidence: Minimum confidence score to include a persona

        Returns:
            Dictionary of generated persona configurations
        """
        logger.info("Starting bulk persona generation...")

        # Get all MITRE groups
        all_groups = self.mitre_client.get_all_groups()
        existing_personas = set(PERSONA_CONFIGS.keys())

        # Find groups needing generation
        groups_to_generate = [
            group for group in all_groups
            if group.get('name') not in existing_personas
        ]

        logger.info(f"Found {len(groups_to_generate)} groups to generate (out of {len(all_groups)} total)")

        # Generate configurations
        generated = {}
        high_confidence = {}
        low_confidence = {}

        for i, group in enumerate(groups_to_generate):
            group_name = group.get('name', f'Unknown_{i}')

            try:
                config = self.generator.generate_persona_config(group)
                confidence = config.get('confidence_score', 0.0)

                generated[group_name] = config

                if confidence >= min_confidence:
                    high_confidence[group_name] = config
                else:
                    low_confidence[group_name] = config

                if (i + 1) % 10 == 0:
                    logger.info(f"Generated {i + 1}/{len(groups_to_generate)} personas...")

            except Exception as e:
                logger.error(f"Failed to generate persona for {group_name}: {e}")
                continue

        # Save results
        self._save_generated_personas(generated, "all_generated_personas.json")
        self._save_generated_personas(high_confidence, "high_confidence_personas.json")
        self._save_generated_personas(low_confidence, "low_confidence_personas.json")

        # Generate summary report
        self._generate_summary_report(generated, high_confidence, low_confidence)

        logger.info(f"Bulk generation complete: {len(generated)} total, "
                   f"{len(high_confidence)} high confidence, {len(low_confidence)} low confidence")

        return generated

    def generate_priority_personas(self, count: int = 20) -> Dict[str, Dict]:
        """
        Generate personas for highest-priority groups based on technique/software count.

        Args:
            count: Number of top groups to generate

        Returns:
            Dictionary of generated persona configurations
        """
        logger.info(f"Generating {count} priority personas...")

        all_groups = self.mitre_client.get_all_groups()
        existing_personas = set(PERSONA_CONFIGS.keys())

        # Score groups by completeness
        group_scores = []
        for group in all_groups:
            if group.get('name') in existing_personas:
                continue  # Skip existing

            techniques = self.mitre_client.get_techniques_for_group(group['id'])
            software = self.mitre_client.get_software_for_group(group['id'])

            score = len(techniques) + len(software)
            if group.get('description'):
                score += 1

            group_scores.append((score, group))

        # Sort by score and take top N
        group_scores.sort(reverse=True)
        priority_groups = [group for _, group in group_scores[:count]]

        # Generate configurations
        generated = {}
        for group in priority_groups:
            group_name = group.get('name', 'Unknown')
            try:
                config = self.generator.generate_persona_config(group)
                generated[group_name] = config
            except Exception as e:
                logger.error(f"Failed to generate priority persona for {group_name}: {e}")

        # Save priority personas
        self._save_generated_personas(generated, "priority_personas.json")

        logger.info(f"Generated {len(generated)} priority personas")
        return generated

    def analyze_coverage_gaps(self) -> Dict:
        """
        Analyze gaps in current persona coverage.

        Returns:
            Analysis report of coverage gaps
        """
        all_groups = self.mitre_client.get_all_groups()
        existing_personas = set(PERSONA_CONFIGS.keys())

        # Regional analysis
        regional_coverage = {}
        industry_coverage = {}
        sophistication_coverage = {'low': 0, 'medium': 0, 'high': 0, 'advanced': 0}

        for group in all_groups:
            group_name = group.get('name', '')
            if group_name in existing_personas:
                continue

            # Analyze missing group
            config = self.generator.generate_persona_config(group)

            # Regional gaps
            for region in config.get('target_regions', []):
                regional_coverage[region] = regional_coverage.get(region, 0) + 1

            # Industry gaps
            for industry in config.get('target_industries', []):
                industry_coverage[industry] = industry_coverage.get(industry, 0) + 1

            # Sophistication gaps
            sophistication = config.get('sophistication_level').value
            sophistication_coverage[sophistication] += 1

        gap_analysis = {
            'total_groups': len(all_groups),
            'covered_groups': len(existing_personas),
            'missing_groups': len(all_groups) - len(existing_personas),
            'coverage_percentage': (len(existing_personas) / len(all_groups)) * 100,
            'regional_gaps': dict(sorted(regional_coverage.items(), key=lambda x: x[1], reverse=True)),
            'industry_gaps': dict(sorted(industry_coverage.items(), key=lambda x: x[1], reverse=True)),
            'sophistication_gaps': sophistication_coverage,
            'top_missing_regions': list(dict(sorted(regional_coverage.items(), key=lambda x: x[1], reverse=True)).keys())[:5],
            'top_missing_industries': list(dict(sorted(industry_coverage.items(), key=lambda x: x[1], reverse=True)).keys())[:5]
        }

        # Save analysis
        self._save_analysis(gap_analysis, "coverage_gap_analysis.json")

        return gap_analysis

    def create_regional_collections(self) -> Dict[str, List[str]]:
        """
        Create regional collections of personas for targeted testing.

        Returns:
            Dictionary mapping regions to persona lists
        """
        all_groups = self.mitre_client.get_all_groups()
        regional_collections = {}

        for group in all_groups:
            group_name = group.get('name', '')
            config = self.generator.generate_persona_config(group)

            for region in config.get('target_regions', []):
                if region not in regional_collections:
                    regional_collections[region] = []
                regional_collections[region].append({
                    'name': group_name,
                    'sophistication': config.get('sophistication_level').value,
                    'confidence': config.get('confidence_score', 0.0)
                })

        # Sort each region by confidence
        for region in regional_collections:
            regional_collections[region].sort(key=lambda x: x['confidence'], reverse=True)

        self._save_analysis(regional_collections, "regional_collections.json")
        return regional_collections

    def export_for_integration(self, format_type: str = "python") -> str:
        """
        Export generated personas in format ready for integration.

        Args:
            format_type: Export format ("python", "json", "yaml")

        Returns:
            Path to exported file
        """
        if format_type == "python":
            return self._export_python_config()
        elif format_type == "json":
            return self._export_json_config()
        elif format_type == "yaml":
            return self._export_yaml_config()
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _export_python_config(self) -> str:
        """Export as Python code for direct integration."""
        # Generate all personas
        generated = self.generate_all_missing_personas()

        # Create Python code
        output_file = self.output_dir / "generated_persona_configs.py"

        with open(output_file, 'w') as f:
            f.write('"""\nGenerated Persona Configurations\n')
            f.write(f'Auto-generated on {datetime.now().isoformat()}\n')
            f.write('"""\n\n')
            f.write('from agent_bounty.attacker_personas.persona import SophisticationLevel, StealthLevel, AttackSpeed\n\n')
            f.write('# Generated persona configurations\n')
            f.write('GENERATED_PERSONA_CONFIGS = {\n')

            for persona_name, config in generated.items():
                f.write(f'    "{persona_name}": {{\n')
                for key, value in config.items():
                    if key in ['sophistication_level', 'stealth_preference', 'attack_speed']:
                        f.write(f'        "{key}": {value.__class__.__name__}.{value.name},\n')
                    elif isinstance(value, str):
                        f.write(f'        "{key}": "{value}",\n')
                    elif isinstance(value, list):
                        f.write(f'        "{key}": {value},\n')
                    else:
                        f.write(f'        "{key}": {value},\n')
                f.write('    },\n')

            f.write('}\n')

        logger.info(f"Exported Python configuration to {output_file}")
        return str(output_file)

    def _export_json_config(self) -> str:
        """Export as JSON."""
        generated = self.generate_all_missing_personas()
        output_file = self.output_dir / "all_personas_config.json"

        # Convert enums to strings for JSON serialization
        json_data = {}
        for name, config in generated.items():
            json_config = {}
            for key, value in config.items():
                if hasattr(value, 'value'):  # Enum
                    json_config[key] = value.value
                else:
                    json_config[key] = value
            json_data[name] = json_config

        with open(output_file, 'w') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_personas': len(json_data),
                    'generator_version': '1.0'
                },
                'personas': json_data
            }, f, indent=2)

        logger.info(f"Exported JSON configuration to {output_file}")
        return str(output_file)

    def _export_yaml_config(self) -> str:
        """Export as YAML (requires PyYAML)."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required for YAML export")

        generated = self.generate_all_missing_personas()
        output_file = self.output_dir / "all_personas_config.yaml"

        # Convert for YAML
        yaml_data = {'personas': {}}
        for name, config in generated.items():
            yaml_config = {}
            for key, value in config.items():
                if hasattr(value, 'value'):  # Enum
                    yaml_config[key] = value.value
                else:
                    yaml_config[key] = value
            yaml_data['personas'][name] = yaml_config

        with open(output_file, 'w') as f:
            yaml.dump(yaml_data, f, default_flow_style=False, indent=2)

        logger.info(f"Exported YAML configuration to {output_file}")
        return str(output_file)

    def _save_generated_personas(self, personas: Dict, filename: str):
        """Save generated personas to JSON file."""
        output_file = self.output_dir / filename

        # Convert enums to strings for JSON
        json_data = {}
        for name, config in personas.items():
            json_config = {}
            for key, value in config.items():
                if hasattr(value, 'value'):  # Enum
                    json_config[key] = value.value
                else:
                    json_config[key] = value
            json_data[name] = json_config

        with open(output_file, 'w') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'count': len(json_data)
                },
                'personas': json_data
            }, f, indent=2)

        logger.info(f"Saved {len(personas)} personas to {output_file}")

    def _save_analysis(self, analysis: Dict, filename: str):
        """Save analysis results."""
        output_file = self.output_dir / filename

        with open(output_file, 'w') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'analysis_type': filename.replace('.json', '')
                },
                'data': analysis
            }, f, indent=2)

        logger.info(f"Saved analysis to {output_file}")

    def _generate_summary_report(self, all_generated: Dict, high_confidence: Dict, low_confidence: Dict):
        """Generate a summary report of the generation process."""
        report = {
            'generation_summary': {
                'total_generated': len(all_generated),
                'high_confidence': len(high_confidence),
                'low_confidence': len(low_confidence),
                'confidence_threshold': 0.3
            },
            'statistics': {
                'sophistication_distribution': self._analyze_sophistication_distribution(all_generated),
                'stealth_distribution': self._analyze_stealth_distribution(all_generated),
                'top_target_industries': self._analyze_target_industries(all_generated),
                'motivation_distribution': self._analyze_motivations(all_generated)
            },
            'recommendations': self._generate_integration_recommendations(high_confidence, low_confidence)
        }

        self._save_analysis(report, "generation_summary_report.json")

    def _analyze_sophistication_distribution(self, personas: Dict) -> Dict:
        """Analyze sophistication level distribution."""
        distribution = {'low': 0, 'medium': 0, 'high': 0, 'advanced': 0}
        for config in personas.values():
            level = config.get('sophistication_level')
            if hasattr(level, 'value'):
                distribution[level.value] += 1
        return distribution

    def _analyze_stealth_distribution(self, personas: Dict) -> Dict:
        """Analyze stealth preference distribution."""
        distribution = {'noisy': 0, 'balanced': 0, 'stealthy': 0}
        for config in personas.values():
            stealth = config.get('stealth_preference')
            if hasattr(stealth, 'value'):
                distribution[stealth.value] += 1
        return distribution

    def _analyze_target_industries(self, personas: Dict) -> List[str]:
        """Get top target industries."""
        industry_count = {}
        for config in personas.values():
            for industry in config.get('target_industries', []):
                industry_count[industry] = industry_count.get(industry, 0) + 1

        return sorted(industry_count.items(), key=lambda x: x[1], reverse=True)[:10]

    def _analyze_motivations(self, personas: Dict) -> Dict:
        """Analyze motivation distribution."""
        motivation_count = {}
        for config in personas.values():
            for motivation in config.get('motivations', []):
                motivation_count[motivation] = motivation_count.get(motivation, 0) + 1
        return motivation_count

    def _generate_integration_recommendations(self, high_confidence: Dict, low_confidence: Dict) -> List[str]:
        """Generate recommendations for integrating generated personas."""
        recommendations = []

        if len(high_confidence) > 20:
            recommendations.append(f"Consider adding top {min(20, len(high_confidence))} high-confidence personas to PERSONA_CONFIGS")

        if len(low_confidence) > 0:
            recommendations.append(f"{len(low_confidence)} personas have low confidence scores - consider manual review")

        recommendations.append("Use regional collections for targeted penetration testing")
        recommendations.append("Prioritize nation-state level groups for advanced red team exercises")

        return recommendations