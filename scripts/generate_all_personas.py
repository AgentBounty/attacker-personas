#!/usr/bin/env python3
"""
CLI Tool for Bulk Persona Generation
Generates configurations for all 181 MITRE ATT&CK groups
"""

import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient
from agent_bounty.attacker_personas.persona_library import PersonaLibrary
from agent_bounty.attacker_personas.bulk_generator import BulkPersonaGenerator


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('persona_generation.log')
        ]
    )


def generate_all_personas(output_dir: str, format_type: str = "json"):
    """Generate all 181 personas."""
    print("Initializing MITRE client and downloading latest data...")
    mitre_client = MITREStixClient()

    print("Setting up bulk generator...")
    bulk_gen = BulkPersonaGenerator(mitre_client, output_dir)

    print("Generating personas for all MITRE groups...")
    all_personas = bulk_gen.generate_all_missing_personas()

    print(f"Generated {len(all_personas)} personas")

    # Export in requested format
    if format_type == "python":
        export_file = bulk_gen.export_for_integration("python")
        print(f"Exported Python configuration to: {export_file}")
    elif format_type == "json":
        export_file = bulk_gen.export_for_integration("json")
        print(f"Exported JSON configuration to: {export_file}")
    elif format_type == "yaml":
        export_file = bulk_gen.export_for_integration("yaml")
        print(f"Exported YAML configuration to: {export_file}")

    return all_personas


def generate_priority_personas(count: int, output_dir: str):
    """Generate only high-priority personas."""
    print(f"Generating top {count} priority personas...")

    mitre_client = MITREStixClient()
    bulk_gen = BulkPersonaGenerator(mitre_client, output_dir)

    priority_personas = bulk_gen.generate_priority_personas(count)
    print(f"Generated {len(priority_personas)} priority personas")

    return priority_personas


def analyze_coverage():
    """Analyze current coverage gaps."""
    print("Analyzing coverage gaps...")

    mitre_client = MITREStixClient()
    bulk_gen = BulkPersonaGenerator(mitre_client)

    analysis = bulk_gen.analyze_coverage_gaps()

    print(f"\nCoverage Analysis:")
    print(f"  Total MITRE Groups: {analysis['total_groups']}")
    print(f"  Pre-configured: {analysis['covered_groups']}")
    print(f"  Missing: {analysis['missing_groups']}")
    print(f"  Coverage: {analysis['coverage_percentage']:.1f}%")

    print(f"\nTop Missing Regions:")
    for region, count in list(analysis['regional_gaps'].items())[:5]:
        print(f"  {region}: {count} groups")

    print(f"\nTop Missing Industries:")
    for industry, count in list(analysis['industry_gaps'].items())[:5]:
        print(f"  {industry}: {count} groups")

    return analysis


def test_persona(persona_name: str):
    """Test a specific persona generation."""
    print(f"Testing persona generation for: {persona_name}")

    library = PersonaLibrary(auto_generate=True)

    try:
        persona = library.get_persona(persona_name)
        print(f"Successfully generated persona: {persona.name}")
        print(f"  MITRE ID: {persona.mitre_id}")
        print(f"  Sophistication: {persona.sophistication_level.value}")
        print(f"  Stealth: {persona.stealth_preference.value}")
        print(f"  Techniques: {len(persona.techniques)}")
        print(f"  Software: {len(persona.software)}")
        print(f"  Target Industries: {', '.join(persona.target_industries[:3])}")

        return persona

    except Exception as e:
        print(f"Failed to generate persona: {e}")
        return None


def show_stats():
    """Show statistics about personas."""
    library = PersonaLibrary(auto_generate=True)
    stats = library.get_auto_generated_stats()

    print(f"Persona Library Statistics:")
    print(f"  Total MITRE Groups: {stats['total_mitre_groups']}")
    print(f"  Pre-configured Personas: {stats['pre_configured_personas']}")
    print(f"  Auto-generated Personas: {stats['auto_generated_personas']}")
    print(f"  Coverage: {stats['coverage_percentage']:.1f}%")
    print(f"  Auto-generation Enabled: {stats['auto_generation_enabled']}")

    print(f"\nSample Auto-generated Groups:")
    for group in stats['sample_auto_generated']:
        print(f"  - {group}")

    return stats


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate attacker personas for all MITRE ATT&CK groups"
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Generate all personas
    gen_all = subparsers.add_parser('generate-all', help='Generate all 181 personas')
    gen_all.add_argument('--output-dir', default='generated_personas',
                        help='Output directory for generated files')
    gen_all.add_argument('--format', choices=['json', 'python', 'yaml'], default='json',
                        help='Export format')

    # Generate priority personas
    gen_priority = subparsers.add_parser('generate-priority', help='Generate high-priority personas')
    gen_priority.add_argument('--count', type=int, default=20,
                             help='Number of priority personas to generate')
    gen_priority.add_argument('--output-dir', default='generated_personas',
                             help='Output directory for generated files')

    # Analyze coverage
    subparsers.add_parser('analyze', help='Analyze coverage gaps')

    # Test specific persona
    test_cmd = subparsers.add_parser('test', help='Test specific persona generation')
    test_cmd.add_argument('persona_name', help='Name of persona to test')

    # Show statistics
    subparsers.add_parser('stats', help='Show persona statistics')

    # Global options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Execute command
    try:
        if args.command == 'generate-all':
            generate_all_personas(args.output_dir, args.format)
        elif args.command == 'generate-priority':
            generate_priority_personas(args.count, args.output_dir)
        elif args.command == 'analyze':
            analyze_coverage()
        elif args.command == 'test':
            test_persona(args.persona_name)
        elif args.command == 'stats':
            show_stats()
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()