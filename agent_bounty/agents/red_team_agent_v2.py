"""
Enhanced Red Team Agent with Attacker Persona Support
Simulates real-world APT behaviors using MITRE ATT&CK framework
"""

import json
import logging
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from agent_bounty.attacker_personas.persona import AttackerPersona, SophisticationLevel
from agent_bounty.attacker_personas.persona_library import PersonaLibrary
from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient

logger = logging.getLogger(__name__)


class AttackPhase(str, Enum):
    """Attack kill chain phases."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AttackStatus(str, Enum):
    """Attack execution status."""
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    ABANDONED = "abandoned"


class RedTeamAgentWithPersona:
    """
    Red Team agent that simulates attacks using real APT personas.

    This agent executes attacks following the TTPs of specific threat actors,
    providing realistic security testing based on MITRE ATT&CK framework.
    """

    def __init__(self, persona_name: Optional[str] = None,
                 mitre_client: Optional[MITREStixClient] = None):
        """
        Initialize Red Team agent.

        Args:
            persona_name: Initial persona to load
            mitre_client: MITRE STIX client instance
        """
        self.mitre_client = mitre_client or MITREStixClient()
        self.persona_library = PersonaLibrary(self.mitre_client)
        self.persona: Optional[AttackerPersona] = None
        self.attack_history = []
        self.current_campaign = None
        self.target_info = {}

        if persona_name:
            self.set_persona(persona_name)

    def set_persona(self, persona_name: str):
        """
        Switch to different attacker persona.

        Args:
            persona_name: Name of the persona (e.g., "APT29", "Lazarus Group")
        """
        self.persona = self.persona_library.get_persona(persona_name)
        logger.info(
            f"Persona set to: {self.persona.name} ({self.persona.mitre_id})"
            f" - {len(self.persona.techniques)} techniques available"
        )

    def list_available_personas(self) -> List[str]:
        """Get list of available attacker personas."""
        return self.persona_library.list_available_personas()

    def execute_attack_campaign(self, target: str,
                               scenario: str = "full_chain",
                               max_duration_hours: int = 24,
                               auto_execute: bool = False) -> Dict:
        """
        Execute attack campaign following persona's TTPs.

        Args:
            target: Target system/network identifier
            scenario: Attack scenario type
            max_duration_hours: Maximum campaign duration
            auto_execute: Whether to automatically execute techniques

        Returns:
            Campaign execution results
        """
        if not self.persona:
            raise ValueError("No persona set. Use set_persona() first.")

        campaign_id = f"campaign_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(
            f"Starting campaign {campaign_id} as {self.persona.name} against {target}"
        )

        # Initialize campaign
        self.current_campaign = {
            'id': campaign_id,
            'persona': self.persona.to_dict(),
            'target': target,
            'scenario': scenario,
            'start_time': datetime.now().isoformat(),
            'max_duration_hours': max_duration_hours,
            'status': 'active',
            'phases': [],
            'techniques_used': [],
            'objectives_completed': [],
            'detection_events': [],
            'data_exfiltrated': 0
        }

        # Generate attack plan
        attack_plan = self._generate_persona_attack_plan(scenario)
        self.current_campaign['attack_plan'] = attack_plan

        # Execute attack phases
        for phase in attack_plan:
            if auto_execute:
                phase_result = self._execute_phase(phase, target)
                self.current_campaign['phases'].append(phase_result)

                # Check if detected or blocked
                if phase_result['status'] in [AttackStatus.BLOCKED, AttackStatus.FAILED]:
                    if self.persona.should_use_stealth_technique():
                        logger.info("Detected/blocked - switching to stealthier approach")
                        # Try alternative technique
                        alt_phase = self._get_alternative_technique(phase)
                        if alt_phase:
                            alt_result = self._execute_phase(alt_phase, target)
                            self.current_campaign['phases'].append(alt_result)
                    else:
                        logger.info("Detected/blocked - persona doesn't prioritize stealth, continuing")
            else:
                # Just plan, don't execute
                self.current_campaign['phases'].append({
                    'phase': phase,
                    'status': AttackStatus.PLANNED
                })

        # Finalize campaign
        self.current_campaign['end_time'] = datetime.now().isoformat()
        self.current_campaign['status'] = 'completed'
        self._calculate_campaign_metrics()

        # Add to history
        self.attack_history.append(self.current_campaign)

        return self.current_campaign

    def _generate_persona_attack_plan(self, scenario: str) -> List[Dict]:
        """
        Generate attack plan based on persona's techniques and scenario.

        Args:
            scenario: Attack scenario type

        Returns:
            Ordered list of attack phases
        """
        plan = []

        # Get attack chain from persona
        attack_chain = self.persona.get_attack_chain(scenario)

        for phase in attack_chain:
            # Add timing based on persona's attack speed
            delay = self._calculate_phase_delay()

            plan.append({
                'tactic': phase['tactic'],
                'technique_id': phase['technique_id'],
                'technique_name': phase['technique_name'],
                'description': phase['description'],
                'expected_delay_minutes': delay,
                'stealth_mode': self.persona.should_use_stealth_technique(),
                'priority': self._get_tactic_priority(phase['tactic'])
            })

        logger.info(f"Generated attack plan with {len(plan)} phases")
        return plan

    def _execute_phase(self, phase: Dict, target: str) -> Dict:
        """
        Execute a single attack phase.

        Args:
            phase: Phase configuration
            target: Target identifier

        Returns:
            Phase execution results
        """
        logger.info(
            f"Executing {phase['tactic']}: {phase['technique_name']} "
            f"({phase['technique_id']})"
        )

        # Simulate execution delay
        if phase.get('expected_delay_minutes', 0) > 0:
            delay_seconds = phase['expected_delay_minutes'] * 60
            logger.debug(f"Waiting {delay_seconds} seconds before execution")
            # In production, this would be async or scheduled
            # time.sleep(min(delay_seconds, 5))  # Cap at 5 seconds for demo

        # Determine success based on persona characteristics
        success_probability = self._calculate_success_probability(phase)
        detection_probability = self._calculate_detection_probability(phase)

        success = random.random() < success_probability
        detected = random.random() < detection_probability

        # Build result
        result = {
            'phase_id': f"{phase['tactic']}_{int(time.time())}",
            'tactic': phase['tactic'],
            'technique_id': phase['technique_id'],
            'technique_name': phase['technique_name'],
            'target': target,
            'start_time': datetime.now().isoformat(),
            'status': AttackStatus.SUCCESS if success else AttackStatus.FAILED,
            'detected': detected,
            'artifacts': self._generate_attack_artifacts(phase),
            'indicators': self._generate_indicators(phase),
            'mitigation_suggestions': self._get_mitigation_suggestions(phase['technique_id'])
        }

        # Handle detection
        if detected:
            self.current_campaign['detection_events'].append({
                'phase': phase['tactic'],
                'technique': phase['technique_id'],
                'timestamp': datetime.now().isoformat(),
                'severity': 'high' if phase['tactic'] in ['impact', 'exfiltration'] else 'medium'
            })

            # Check if blocked
            if random.random() < 0.3:  # 30% chance of being blocked if detected
                result['status'] = AttackStatus.BLOCKED
                logger.warning(f"Attack blocked: {phase['technique_name']}")

        # Track successful techniques
        if result['status'] == AttackStatus.SUCCESS:
            self.current_campaign['techniques_used'].append(phase['technique_id'])

            # Track objectives
            if phase['tactic'] == 'initial-access':
                self.current_campaign['objectives_completed'].append('initial_access')
            elif phase['tactic'] == 'persistence':
                self.current_campaign['objectives_completed'].append('persistence_established')
            elif phase['tactic'] == 'exfiltration':
                self.current_campaign['objectives_completed'].append('data_exfiltrated')
                self.current_campaign['data_exfiltrated'] += random.randint(1, 100)  # MB

        result['end_time'] = datetime.now().isoformat()
        return result

    def _calculate_phase_delay(self) -> int:
        """Calculate delay between attack phases based on persona."""
        base_delays = {
            'slow': random.randint(60, 240),      # 1-4 hours
            'moderate': random.randint(15, 60),   # 15-60 minutes
            'fast': random.randint(1, 15),        # 1-15 minutes
            'aggressive': random.randint(0, 2)     # 0-2 minutes
        }

        speed = self.persona.attack_speed.value
        delay = base_delays.get(speed, 30)

        # Add randomization based on stealth
        if self.persona.stealth_preference.value == 'stealthy':
            delay *= random.uniform(1.5, 2.5)

        return int(delay)

    def _calculate_success_probability(self, phase: Dict) -> float:
        """Calculate probability of technique success."""
        base_prob = self.persona.technique_success_rate

        # Adjust based on sophistication
        sophistication_modifiers = {
            SophisticationLevel.LOW: 0.8,
            SophisticationLevel.MEDIUM: 0.9,
            SophisticationLevel.HIGH: 1.0,
            SophisticationLevel.ADVANCED: 1.1
        }

        base_prob *= sophistication_modifiers.get(
            self.persona.sophistication_level, 1.0
        )

        # Adjust based on tactic difficulty
        difficult_tactics = ['privilege-escalation', 'defense-evasion', 'persistence']
        if phase['tactic'] in difficult_tactics:
            base_prob *= 0.85

        return min(base_prob, 0.95)  # Cap at 95%

    def _calculate_detection_probability(self, phase: Dict) -> float:
        """Calculate probability of being detected."""
        # Base detection probability
        base_detection = 0.3

        # Adjust based on stealth preference
        if self.persona.stealth_preference.value == 'stealthy':
            base_detection *= 0.5
        elif self.persona.stealth_preference.value == 'noisy':
            base_detection *= 1.5

        # High-visibility tactics more likely to be detected
        high_visibility = ['impact', 'exfiltration', 'lateral-movement']
        if phase['tactic'] in high_visibility:
            base_detection *= 1.3

        # Stealth mode reduces detection
        if phase.get('stealth_mode'):
            base_detection *= 0.6

        return min(base_detection, 0.9)  # Cap at 90%

    def _get_tactic_priority(self, tactic: str) -> int:
        """Get execution priority for a tactic based on persona goals."""
        priority_map = {
            'initial-access': 10,
            'execution': 9,
            'persistence': 8 if self.persona.persistence_priority > 0.7 else 5,
            'privilege-escalation': 7,
            'defense-evasion': 8 if self.persona.stealth_preference.value == 'stealthy' else 4,
            'credential-access': 6,
            'discovery': 5,
            'lateral-movement': 6,
            'collection': 7 if self.persona.data_exfiltration_priority > 0.7 else 3,
            'command-and-control': 6,
            'exfiltration': 8 if self.persona.data_exfiltration_priority > 0.7 else 3,
            'impact': 4
        }
        return priority_map.get(tactic, 5)

    def _get_alternative_technique(self, original_phase: Dict) -> Optional[Dict]:
        """Find alternative technique for the same tactic."""
        # Get alternative technique from persona
        alternative = self.persona.select_technique_for_tactic(
            original_phase['tactic'],
            exclude=[original_phase['technique_id']]
        )

        if alternative:
            return {
                'tactic': original_phase['tactic'],
                'technique_id': alternative.get('external_id', ''),
                'technique_name': alternative.get('name', ''),
                'description': alternative.get('description', '')[:200],
                'expected_delay_minutes': self._calculate_phase_delay(),
                'stealth_mode': True,  # Use stealth for alternative
                'priority': original_phase.get('priority', 5)
            }
        return None

    def _generate_attack_artifacts(self, phase: Dict) -> List[Dict]:
        """Generate realistic attack artifacts for the phase."""
        artifacts = []

        # Common artifacts by tactic
        if phase['tactic'] == 'initial-access':
            artifacts.append({
                'type': 'network',
                'description': 'Suspicious external connection',
                'ioc': f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            })
        elif phase['tactic'] == 'execution':
            artifacts.append({
                'type': 'process',
                'description': 'Suspicious process execution',
                'ioc': random.choice(['powershell.exe', 'cmd.exe', 'wscript.exe'])
            })
        elif phase['tactic'] == 'persistence':
            artifacts.append({
                'type': 'registry',
                'description': 'Registry key modification',
                'ioc': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            })
        elif phase['tactic'] == 'exfiltration':
            artifacts.append({
                'type': 'network',
                'description': 'Large data transfer',
                'ioc': f"{random.randint(10, 500)} MB uploaded"
            })

        return artifacts

    def _generate_indicators(self, phase: Dict) -> List[str]:
        """Generate indicators of compromise for the phase."""
        indicators = []

        # Add technique-specific indicators
        technique_id = phase['technique_id']
        if 'T1566' in technique_id:  # Phishing
            indicators.append("Suspicious email with attachment")
            indicators.append("User clicked on external link")
        elif 'T1055' in technique_id:  # Process Injection
            indicators.append("Process memory modification detected")
            indicators.append("Unusual process behavior")
        elif 'T1003' in technique_id:  # Credential Dumping
            indicators.append("lsass.exe access detected")
            indicators.append("Suspicious credential access")
        elif 'T1041' in technique_id:  # Exfiltration Over C2
            indicators.append("Unusual outbound traffic volume")
            indicators.append("Connection to known C2 infrastructure")

        return indicators

    def _get_mitigation_suggestions(self, technique_id: str) -> List[str]:
        """Get mitigation suggestions for a technique."""
        mitigations = []

        # Get technique details
        technique = self.mitre_client.get_technique_by_id(technique_id)
        if not technique:
            return ["Implement defense-in-depth strategy"]

        # Common mitigations by tactic
        for phase in technique.get('kill_chain_phases', []):
            tactic = phase.get('phase_name')
            if tactic == 'initial-access':
                mitigations.extend([
                    "Implement email filtering and sandboxing",
                    "User security awareness training",
                    "Network segmentation"
                ])
            elif tactic == 'execution':
                mitigations.extend([
                    "Application whitelisting",
                    "Disable unnecessary scripting engines",
                    "Monitor process creation"
                ])
            elif tactic == 'persistence':
                mitigations.extend([
                    "Regular system audits",
                    "Monitor autostart locations",
                    "Implement least privilege"
                ])
            elif tactic == 'exfiltration':
                mitigations.extend([
                    "Data loss prevention (DLP)",
                    "Network traffic monitoring",
                    "Encrypt sensitive data"
                ])

        return list(set(mitigations))[:3]  # Return top 3 unique mitigations

    def _calculate_campaign_metrics(self):
        """Calculate overall campaign metrics."""
        if not self.current_campaign:
            return

        # Success rate
        total_phases = len(self.current_campaign['phases'])
        successful_phases = sum(
            1 for p in self.current_campaign['phases']
            if p.get('status') == AttackStatus.SUCCESS
        )
        self.current_campaign['success_rate'] = (
            successful_phases / total_phases if total_phases > 0 else 0
        )

        # Detection rate
        detected_phases = sum(
            1 for p in self.current_campaign['phases']
            if p.get('detected', False)
        )
        self.current_campaign['detection_rate'] = (
            detected_phases / total_phases if total_phases > 0 else 0
        )

        # Campaign objectives
        objectives = {
            'initial_access': 'initial_access' in self.current_campaign['objectives_completed'],
            'persistence': 'persistence_established' in self.current_campaign['objectives_completed'],
            'data_theft': 'data_exfiltrated' in self.current_campaign['objectives_completed'],
            'lateral_movement': any('lateral-movement' in p['tactic']
                                   for p in self.current_campaign['phases']
                                   if p.get('status') == AttackStatus.SUCCESS)
        }
        self.current_campaign['objectives_achieved'] = objectives

        # Risk score (0-100)
        risk_score = 0
        if objectives['initial_access']:
            risk_score += 20
        if objectives['persistence']:
            risk_score += 25
        if objectives['data_theft']:
            risk_score += 30
        if objectives['lateral_movement']:
            risk_score += 25

        # Adjust for detection
        risk_score *= (1 - self.current_campaign['detection_rate'] * 0.3)
        self.current_campaign['risk_score'] = min(int(risk_score), 100)

    def generate_attack_report(self, campaign_id: Optional[str] = None) -> Dict:
        """
        Generate comprehensive attack report.

        Args:
            campaign_id: Specific campaign ID or None for latest

        Returns:
            Detailed attack report
        """
        if campaign_id:
            campaign = next((c for c in self.attack_history if c['id'] == campaign_id), None)
        else:
            campaign = self.current_campaign

        if not campaign:
            return {'error': 'No campaign found'}

        return {
            'campaign_id': campaign['id'],
            'persona': campaign['persona']['name'],
            'mitre_id': campaign['persona']['mitre_id'],
            'target': campaign['target'],
            'duration': self._calculate_duration(campaign),
            'techniques_used': campaign['techniques_used'],
            'success_rate': f"{campaign.get('success_rate', 0) * 100:.1f}%",
            'detection_rate': f"{campaign.get('detection_rate', 0) * 100:.1f}%",
            'risk_score': campaign.get('risk_score', 0),
            'data_exfiltrated_mb': campaign.get('data_exfiltrated', 0),
            'objectives_achieved': campaign.get('objectives_achieved', {}),
            'key_findings': self._generate_key_findings(campaign),
            'recommendations': self._generate_recommendations(campaign)
        }

    def _calculate_duration(self, campaign: Dict) -> str:
        """Calculate campaign duration."""
        if 'start_time' not in campaign or 'end_time' not in campaign:
            return "Unknown"

        start = datetime.fromisoformat(campaign['start_time'])
        end = datetime.fromisoformat(campaign['end_time'])
        duration = end - start

        hours = duration.total_seconds() / 3600
        if hours < 1:
            return f"{int(duration.total_seconds() / 60)} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        else:
            return f"{hours / 24:.1f} days"

    def _generate_key_findings(self, campaign: Dict) -> List[str]:
        """Generate key findings from the campaign."""
        findings = []

        # Success-based findings
        if campaign.get('success_rate', 0) > 0.7:
            findings.append("High success rate indicates weak defensive controls")
        elif campaign.get('success_rate', 0) < 0.3:
            findings.append("Low success rate shows effective security measures")

        # Detection-based findings
        if campaign.get('detection_rate', 0) < 0.3:
            findings.append("Low detection rate - improve monitoring capabilities")
        elif campaign.get('detection_rate', 0) > 0.7:
            findings.append("Good detection capabilities in place")

        # Objective-based findings
        objectives = campaign.get('objectives_achieved', {})
        if objectives.get('persistence'):
            findings.append("Attacker achieved persistence - system compromise likely")
        if objectives.get('data_theft'):
            findings.append(f"Data exfiltration successful - {campaign.get('data_exfiltrated', 0)} MB stolen")
        if objectives.get('lateral_movement'):
            findings.append("Lateral movement achieved - network segmentation issues")

        return findings

    def _generate_recommendations(self, campaign: Dict) -> List[str]:
        """Generate security recommendations based on campaign results."""
        recommendations = []

        # Analyze successful techniques
        for phase in campaign.get('phases', []):
            if phase.get('status') == AttackStatus.SUCCESS:
                tactic = phase.get('tactic')
                if tactic == 'initial-access' and not phase.get('detected'):
                    recommendations.append("Enhance email security and user awareness training")
                elif tactic == 'persistence' and not phase.get('detected'):
                    recommendations.append("Implement system integrity monitoring")
                elif tactic == 'lateral-movement':
                    recommendations.append("Improve network segmentation and access controls")
                elif tactic == 'exfiltration':
                    recommendations.append("Deploy data loss prevention (DLP) solutions")

        # General recommendations based on metrics
        if campaign.get('detection_rate', 0) < 0.5:
            recommendations.append("Enhance security monitoring and alerting")
        if campaign.get('risk_score', 0) > 70:
            recommendations.append("Critical: Immediate security posture review required")

        # Remove duplicates and limit
        return list(set(recommendations))[:5]