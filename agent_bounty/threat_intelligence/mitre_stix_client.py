"""
MITRE ATT&CK STIX 2.1 Client
Downloads and parses MITRE ATT&CK data from official STIX repository
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import requests
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)


class MITREStixClient:
    """
    Client for downloading and parsing MITRE ATT&CK STIX 2.1 data.

    Fetches data from the official MITRE ATT&CK STIX repository and
    provides methods to query groups, techniques, and relationships.
    """

    STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    VERSION_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

    def __init__(self, cache_dir: str = "data/mitre_attack", auto_update: bool = True):
        """
        Initialize MITRE STIX client.

        Args:
            cache_dir: Directory to cache STIX data
            auto_update: Whether to check for updates on init
        """
        self.cache_dir = Path(cache_dir)
        self.cache_file = self.cache_dir / "enterprise-attack.json"
        self.metadata_file = self.cache_dir / "metadata.json"
        self.stix_data = None
        self._objects_by_type = {}
        self._objects_by_id = {}
        self._relationships = []

        self._ensure_cache_dir()
        self._load_or_download(auto_update)

    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_or_download(self, auto_update: bool = True):
        """Load from cache or download if missing/outdated."""
        if not self.cache_file.exists():
            logger.info("STIX data not found in cache. Downloading...")
            self.download_latest()
        elif auto_update and self._is_cache_outdated():
            logger.info("STIX data cache is outdated. Downloading latest...")
            self.download_latest()
        else:
            logger.info("Loading STIX data from cache...")
            self._load_from_cache()

        self._parse_stix_data()

    def _is_cache_outdated(self, max_age_days: int = 7) -> bool:
        """Check if cached data is older than max_age_days."""
        if not self.metadata_file.exists():
            return True

        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)

            download_time = date_parser.parse(metadata.get('download_time', ''))
            age = datetime.now() - download_time
            return age > timedelta(days=max_age_days)
        except Exception as e:
            logger.warning(f"Could not check cache age: {e}")
            return True

    def download_latest(self):
        """Download latest STIX data from GitHub."""
        try:
            logger.info(f"Downloading STIX data from {self.STIX_URL}")

            # Download with progress indication
            response = requests.get(self.STIX_URL, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            # Write to temporary file first
            temp_file = self.cache_file.with_suffix('.tmp')
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if downloaded % (1024 * 1024) == 0:  # Log every MB
                                logger.info(f"Download progress: {progress:.1f}%")

            # Move to final location
            temp_file.replace(self.cache_file)

            # Save metadata
            metadata = {
                'download_time': datetime.now().isoformat(),
                'source_url': self.STIX_URL,
                'file_size': downloaded
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Successfully downloaded {downloaded / (1024*1024):.1f} MB")

        except requests.RequestException as e:
            logger.error(f"Failed to download STIX data: {e}")
            raise RuntimeError(f"Failed to download STIX data: {e}")

    def _load_from_cache(self):
        """Load STIX data from cache file."""
        try:
            with open(self.cache_file, 'r') as f:
                self.stix_data = json.load(f)
            logger.info(f"Loaded {len(self.stix_data.get('objects', []))} STIX objects from cache")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse cached STIX data: {e}")
            raise RuntimeError(f"Failed to parse cached STIX data: {e}")

    def _parse_stix_data(self):
        """Parse STIX data into indexed structures for efficient querying."""
        if not self.stix_data:
            self._load_from_cache()

        # Clear existing indexes
        self._objects_by_type.clear()
        self._objects_by_id.clear()
        self._relationships.clear()

        # Index objects
        for obj in self.stix_data.get('objects', []):
            obj_type = obj.get('type')
            obj_id = obj.get('id')

            # Index by type
            if obj_type not in self._objects_by_type:
                self._objects_by_type[obj_type] = []
            self._objects_by_type[obj_type].append(obj)

            # Index by ID
            if obj_id:
                self._objects_by_id[obj_id] = obj

            # Special handling for relationships
            if obj_type == 'relationship':
                self._relationships.append(obj)

        logger.info(f"Indexed {len(self._objects_by_id)} objects across {len(self._objects_by_type)} types")

    def get_group_by_name(self, name: str) -> Optional[Dict]:
        """
        Find intrusion-set (group) by name or alias.

        Args:
            name: Group name or alias (e.g., "APT29", "Cozy Bear")

        Returns:
            Group object or None if not found
        """
        intrusion_sets = self._objects_by_type.get('intrusion-set', [])

        for group in intrusion_sets:
            # Check primary name
            if group.get('name', '').lower() == name.lower():
                return group

            # Check aliases
            aliases = group.get('aliases', [])
            if any(alias.lower() == name.lower() for alias in aliases):
                return group

        logger.warning(f"Group not found: {name}")
        return None

    def get_techniques_for_group(self, group_id: str) -> List[Dict]:
        """
        Get all techniques used by a group via relationships.

        Args:
            group_id: STIX ID of the intrusion-set

        Returns:
            List of attack-pattern objects
        """
        techniques = []

        # Find relationships where source is the group
        for rel in self._relationships:
            if (rel.get('source_ref') == group_id and
                rel.get('relationship_type') == 'uses'):

                target_ref = rel.get('target_ref')
                target = self._objects_by_id.get(target_ref)

                # Check if target is an attack-pattern (technique)
                if target and target.get('type') == 'attack-pattern':
                    # Add MITRE ID from external references
                    technique = dict(target)
                    for ref in technique.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            technique['external_id'] = ref.get('external_id')
                            break
                    techniques.append(technique)

        logger.info(f"Found {len(techniques)} techniques for group {group_id}")
        return techniques

    def get_software_for_group(self, group_id: str) -> List[Dict]:
        """
        Get malware/tools used by group.

        Args:
            group_id: STIX ID of the intrusion-set

        Returns:
            List of malware and tool objects
        """
        software = []

        for rel in self._relationships:
            if (rel.get('source_ref') == group_id and
                rel.get('relationship_type') == 'uses'):

                target_ref = rel.get('target_ref')
                target = self._objects_by_id.get(target_ref)

                # Check if target is malware or tool
                if target and target.get('type') in ['malware', 'tool']:
                    # Add MITRE ID from external references
                    soft = dict(target)
                    for ref in soft.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            soft['external_id'] = ref.get('external_id')
                            break
                    software.append(soft)

        logger.info(f"Found {len(software)} software items for group {group_id}")
        return software

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """
        Get technique details by ATT&CK ID (e.g., T1566.001).

        Args:
            technique_id: MITRE ATT&CK ID

        Returns:
            Attack-pattern object or None if not found
        """
        attack_patterns = self._objects_by_type.get('attack-pattern', [])

        for pattern in attack_patterns:
            for ref in pattern.get('external_references', []):
                if (ref.get('source_name') == 'mitre-attack' and
                    ref.get('external_id') == technique_id):
                    # Add the external ID to the pattern object for convenience
                    result = dict(pattern)
                    result['external_id'] = technique_id
                    return result

        logger.warning(f"Technique not found: {technique_id}")
        return None

    def get_all_groups(self) -> List[Dict]:
        """Get all intrusion sets (groups) in the dataset."""
        groups = []
        for group in self._objects_by_type.get('intrusion-set', []):
            # Add MITRE ID for convenience
            g = dict(group)
            for ref in g.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    g['mitre_id'] = ref.get('external_id')
                    break
            groups.append(g)
        return groups

    def get_tactics(self) -> List[str]:
        """Get unique list of all tactics from techniques."""
        tactics = set()
        for pattern in self._objects_by_type.get('attack-pattern', []):
            for phase in pattern.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.add(phase.get('phase_name'))
        return sorted(list(tactics))

    def refresh_cache(self):
        """Force download of latest STIX data."""
        logger.info("Forcing cache refresh...")
        self.download_latest()
        self._parse_stix_data()