"""
IOC (Indicators of Compromise) extraction from text using regex patterns
"""

import re
from typing import Dict, List
import logging
from ..core.config import Config

logger = logging.getLogger(__name__)

class IOCExtractor:
    """Extract Indicators of Compromise from text using regex patterns"""
    
    def __init__(self):
        self.patterns = Config.IOC_PATTERNS
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOCs from given text"""
        iocs = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Remove duplicates and filter out common false positives
            filtered_matches = list(set(self._filter_false_positives(matches, ioc_type)))
            if filtered_matches:
                iocs[ioc_type] = filtered_matches
        
        return iocs
    
    def _filter_false_positives(self, matches: List[str], ioc_type: str) -> List[str]:
        """Filter out common false positives"""
        if ioc_type == 'ip_addresses':
            return self._filter_ip_addresses(matches)
        elif ioc_type == 'domains':
            return self._filter_domains(matches)
        
        return matches
    
    def _filter_ip_addresses(self, ips: List[str]) -> List[str]:
        """Filter out private IP ranges and invalid IPs"""
        filtered = []
        for ip in ips:
            octets = ip.split('.')
            if len(octets) == 4:
                try:
                    octet_values = [int(octet) for octet in octets]
                    if all(0 <= octet <= 255 for octet in octet_values):
                        # Skip private IP ranges for threat intel purposes
                        first_octet = octet_values[0]
                        if not (first_octet in [10, 127] or 
                               (first_octet == 172 and 16 <= octet_values[1] <= 31) or
                               (first_octet == 192 and octet_values[1] == 168)):
                            filtered.append(ip)
                except ValueError:
                    continue
        return filtered
    
    def _filter_domains(self, domains: List[str]) -> List[str]:
        """Filter out common domains that aren't threats"""
        return [d for d in domains if d.lower() not in Config.EXCLUDE_DOMAINS]
