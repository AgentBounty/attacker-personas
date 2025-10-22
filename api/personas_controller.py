"""
FastAPI Controller for Attacker Personas
Provides REST API endpoints for managing and executing persona-based attacks
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

from agent_bounty.threat_intelligence.mitre_stix_client import MITREStixClient
from agent_bounty.attacker_personas.persona_library import PersonaLibrary
from agent_bounty.attacker_personas.persona import SophisticationLevel, StealthLevel
from agent_bounty.agents.red_team_agent_v2 import RedTeamAgentWithPersona

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/personas", tags=["Attacker Personas"])

# Global instances (in production, use dependency injection)
_mitre_client = None
_persona_library = None


def get_mitre_client() -> MITREStixClient:
    """Get or create MITRE client singleton."""
    global _mitre_client
    if _mitre_client is None:
        _mitre_client = MITREStixClient()
    return _mitre_client


def get_persona_library() -> PersonaLibrary:
    """Get or create persona library singleton."""
    global _persona_library
    if _persona_library is None:
        _persona_library = PersonaLibrary(get_mitre_client())
    return _persona_library


# Pydantic models for API

class PersonaResponse(BaseModel):
    """Persona summary response."""
    name: str
    mitre_id: str
    sophistication: str
    stealth: str
    attack_speed: str
    industries: List[str]
    regions: List[str]
    motivations: List[str]
    technique_count: int
    software_count: int
    description: str

    class Config:
        schema_extra = {
            "example": {
                "name": "APT29",
                "mitre_id": "G0016",
                "sophistication": "advanced",
                "stealth": "stealthy",
                "attack_speed": "slow",
                "industries": ["Government", "Technology"],
                "regions": ["North America", "Europe"],
                "motivations": ["espionage"],
                "technique_count": 64,
                "software_count": 23,
                "description": "Russian state-sponsored group..."
            }
        }


class PersonaDetailResponse(BaseModel):
    """Detailed persona information."""
    persona: Dict[str, Any]
    tactics: List[str]
    top_techniques: List[Dict[str, str]]
    top_software: List[Dict[str, str]]
    attack_chain_sample: List[Dict[str, Any]]


class AttackRequest(BaseModel):
    """Request to execute attack with persona."""
    target: str = Field(..., description="Target system/network identifier")
    persona: str = Field(..., description="Attacker persona name")
    scenario: str = Field("full_chain", description="Attack scenario type")
    auto_execute: bool = Field(False, description="Auto-execute techniques")
    max_duration_hours: int = Field(24, ge=1, le=168, description="Max campaign duration")

    class Config:
        schema_extra = {
            "example": {
                "target": "192.168.1.0/24",
                "persona": "APT29",
                "scenario": "full_chain",
                "auto_execute": True,
                "max_duration_hours": 12
            }
        }


class AttackResponse(BaseModel):
    """Attack execution response."""
    success: bool
    campaign_id: str
    message: str
    summary: Optional[Dict[str, Any]]


class CustomPersonaRequest(BaseModel):
    """Request to create custom persona."""
    name: str = Field(..., description="Custom persona name")
    base_persona: Optional[str] = Field(None, description="Base persona to inherit from")
    sophistication_level: str = Field("medium", description="Sophistication level")
    stealth_preference: str = Field("balanced", description="Stealth preference")
    target_industries: List[str] = Field([], description="Target industries")
    motivations: List[str] = Field([], description="Attack motivations")
    description: str = Field("", description="Persona description")


# Endpoints

@router.get("/", response_model=List[PersonaResponse])
async def list_personas(
    sophistication: Optional[str] = Query(None, description="Filter by sophistication level"),
    industry: Optional[str] = Query(None, description="Filter by target industry"),
    motivation: Optional[str] = Query(None, description="Filter by motivation")
):
    """
    List all available attacker personas with optional filtering.

    Returns pre-configured APT groups from MITRE ATT&CK framework.
    """
    try:
        persona_lib = get_persona_library()
        persona_names = persona_lib.list_available_personas()

        # Apply filters
        if sophistication:
            try:
                level = SophisticationLevel(sophistication.lower())
                persona_names = [
                    name for name in persona_names
                    if name in persona_lib.get_personas_by_sophistication(level)
                ]
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid sophistication level: {sophistication}"
                )

        if industry:
            filtered = persona_lib.get_personas_by_industry(industry)
            persona_names = [name for name in persona_names if name in filtered]

        if motivation:
            filtered = persona_lib.get_personas_by_motivation(motivation)
            persona_names = [name for name in persona_names if name in filtered]

        # Build response
        personas = []
        for name in persona_names:
            try:
                persona = persona_lib.get_persona(name)
                personas.append(PersonaResponse(
                    name=persona.name,
                    mitre_id=persona.mitre_id,
                    sophistication=persona.sophistication_level.value,
                    stealth=persona.stealth_preference.value,
                    attack_speed=persona.attack_speed.value,
                    industries=persona.target_industries,
                    regions=persona.target_regions,
                    motivations=persona.motivations,
                    technique_count=len(persona.techniques),
                    software_count=len(persona.software),
                    description=persona.description[:200] if persona.description else ""
                ))
            except Exception as e:
                logger.error(f"Error loading persona {name}: {e}")
                continue

        return personas

    except Exception as e:
        logger.error(f"Error listing personas: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{persona_name}", response_model=PersonaDetailResponse)
async def get_persona_details(persona_name: str):
    """
    Get detailed information about a specific persona.

    Returns full persona profile including techniques, tools, and sample attack chain.
    """
    try:
        persona_lib = get_persona_library()
        persona = persona_lib.get_persona(persona_name)

        # Get top techniques
        top_techniques = []
        for tech in persona.techniques[:10]:
            top_techniques.append({
                "id": tech.get("external_id", ""),
                "name": tech.get("name", ""),
                "tactics": [
                    phase.get("phase_name", "")
                    for phase in tech.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]
            })

        # Get top software
        top_software = []
        for soft in persona.software[:10]:
            top_software.append({
                "id": soft.get("external_id", ""),
                "name": soft.get("name", ""),
                "type": soft.get("type", "")
            })

        # Generate sample attack chain
        attack_chain = persona.get_attack_chain("full_chain")

        return PersonaDetailResponse(
            persona=persona.to_dict(),
            tactics=persona.tactics,
            top_techniques=top_techniques,
            top_software=top_software,
            attack_chain_sample=attack_chain[:10]  # First 10 phases
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting persona details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack", response_model=AttackResponse)
async def execute_attack(request: AttackRequest, background_tasks: BackgroundTasks):
    """
    Execute red team attack using specified persona.

    Simulates attack campaign following the TTPs of the selected threat actor.
    """
    try:
        # Initialize agent with persona
        agent = RedTeamAgentWithPersona(persona_name=request.persona)

        # Execute attack campaign
        results = agent.execute_attack_campaign(
            target=request.target,
            scenario=request.scenario,
            max_duration_hours=request.max_duration_hours,
            auto_execute=request.auto_execute
        )

        # Generate summary
        summary = {
            "campaign_id": results["id"],
            "persona": results["persona"]["name"],
            "target": results["target"],
            "phases_planned": len(results["attack_plan"]),
            "phases_executed": len(results["phases"]),
            "techniques_used": results["techniques_used"],
            "success_rate": results.get("success_rate", 0),
            "detection_rate": results.get("detection_rate", 0),
            "risk_score": results.get("risk_score", 0),
            "status": results["status"]
        }

        # If auto_execute is False, we could schedule the attack in background
        if not request.auto_execute:
            logger.info(f"Attack campaign {results['id']} planned but not executed")
            message = "Attack campaign planned. Use /execute endpoint to run."
        else:
            message = "Attack campaign executed successfully"

        return AttackResponse(
            success=True,
            campaign_id=results["id"],
            message=message,
            summary=summary
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error executing attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack/{campaign_id}/report")
async def get_attack_report(campaign_id: str):
    """
    Get detailed report for a specific attack campaign.

    Returns comprehensive analysis including techniques used, detection events,
    and security recommendations.
    """
    try:
        # In production, this would fetch from database
        # For now, return a sample report structure
        return {
            "campaign_id": campaign_id,
            "status": "completed",
            "report_generated": datetime.now().isoformat(),
            "message": "Full report generation requires campaign data persistence"
        }

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/custom", response_model=Dict[str, Any])
async def create_custom_persona(request: CustomPersonaRequest):
    """
    Create a custom attacker persona.

    Allows creation of custom threat actor profiles for specific testing scenarios.
    """
    try:
        persona_lib = get_persona_library()

        # Create custom persona
        attributes = {
            "sophistication_level": SophisticationLevel(request.sophistication_level),
            "stealth_preference": StealthLevel(request.stealth_preference),
            "target_industries": request.target_industries,
            "motivations": request.motivations,
            "description": request.description
        }

        persona = persona_lib.create_custom_persona(
            name=request.name,
            base_persona=request.base_persona,
            **attributes
        )

        return {
            "success": True,
            "message": f"Custom persona '{request.name}' created successfully",
            "persona": persona.to_dict()
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating custom persona: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_personas(persona1: str = Query(...), persona2: str = Query(...)):
    """
    Compare two attacker personas.

    Analyzes differences in techniques, sophistication, and capabilities.
    """
    try:
        persona_lib = get_persona_library()
        comparison = persona_lib.compare_personas(persona1, persona2)
        return comparison

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error comparing personas: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitre/refresh")
async def refresh_mitre_data():
    """
    Refresh MITRE ATT&CK data from source.

    Downloads latest STIX data from MITRE repository.
    """
    try:
        mitre_client = get_mitre_client()
        mitre_client.refresh_cache()

        # Clear persona cache
        persona_lib = get_persona_library()
        persona_lib.clear_cache()

        return {
            "success": True,
            "message": "MITRE ATT&CK data refreshed successfully",
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error refreshing MITRE data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mitre/groups")
async def list_mitre_groups(limit: int = Query(50, ge=1, le=200)):
    """
    List all threat groups from MITRE ATT&CK.

    Returns all available groups from the MITRE dataset, not just pre-configured ones.
    """
    try:
        persona_lib = get_persona_library()
        groups = persona_lib.list_all_mitre_groups()[:limit]
        return {
            "total": len(groups),
            "groups": groups
        }

    except Exception as e:
        logger.error(f"Error listing MITRE groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/techniques/{technique_id}")
async def get_technique_details(technique_id: str):
    """
    Get details about a specific MITRE ATT&CK technique.

    Returns technique information including description and mitigations.
    """
    try:
        mitre_client = get_mitre_client()
        technique = mitre_client.get_technique_by_id(technique_id)

        if not technique:
            raise HTTPException(
                status_code=404,
                detail=f"Technique {technique_id} not found"
            )

        return {
            "id": technique.get("external_id"),
            "name": technique.get("name"),
            "description": technique.get("description", ""),
            "platforms": technique.get("x_mitre_platforms", []),
            "tactics": [
                phase.get("phase_name")
                for phase in technique.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
            "detection": technique.get("x_mitre_detection", "")
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting technique details: {e}")
        raise HTTPException(status_code=500, detail=str(e))