import os
import httpx
import redis
import json
import asyncio
import logging
from typing import Dict, List, Optional
from datetime import timedelta
from dotenv import load_dotenv

# Load security environment variables
load_dotenv()

# Logs for SOC auditing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for Threat Intel
VT_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_API_URL = "https://otx.alienvault.com/api/v1/indicators"

class IntelService:
    def __init__(self):
        # API Keys from secure environment
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")

        # Redis Cache for Rate Limit Protection
        try:
            self.redis_client = redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", 6379)),
                db=int(os.getenv("REDIS_DB", 0)),
                decode_responses=True,
                socket_connect_timeout=1 # Critical: Prevent long hang during import
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Threat Intel Cache (Redis) Connected.")
        except Exception as e:
            logger.warning(f"Redis unavailable, running without cache: {e}")
            self.redis_client = None


        # Local Risk Factors (Heuristic Fallback)
        self.malicious_tlds = {'.xyz', '.top', '.pw', '.bid', '.monster', '.icu', '.cloud'}
        self.malicious_keywords = {'tunnel', 'exfil', 'c2', 'dns-tunnel', 'iodine', 'dnscat'}

    async def get_vt_reputation(self, target: str, type: str = "domain") -> Dict:
        """VirusTotal V3 Analysis (Async)"""
        if not self.vt_key: return {}

        cache_key = f"vt:{target}"
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached: return json.loads(cached)

        endpoint = f"{VT_API_URL}/{type}s/{target}"
        headers = {"x-apikey": self.vt_key}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(endpoint, headers=headers, timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    if self.redis_client:
                        self.redis_client.setex(cache_key, timedelta(hours=12), json.dumps(data))
                    return data
        except Exception as e:
            logger.error(f"VirusTotal Error: {e}")
        return {}

    async def get_abuseipdb_score(self, ip: str) -> Optional[int]:
        """AbuseIPDB IP Risk Scoring"""
        if not self.abuseipdb_key: return None

        cache_key = f"abuseipdb:{ip}"
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached: return int(cached)

        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=5.0)
                if resp.status_code == 200:
                    score = resp.json().get('data', {}).get('abuseConfidenceScore', 0)
                    if self.redis_client:
                        self.redis_client.setex(cache_key, timedelta(hours=12), str(score))
                    return score
        except Exception as e:
            logger.error(f"AbuseIPDB Error: {e}")
        return None

    async def get_otx_indicators(self, domain: str) -> List[str]:
        """AlienVault OTX Threat Indicators"""
        if not self.otx_key: return []

        cache_key = f"otx:{domain}"
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached: return json.loads(cached)

        endpoint = f"{OTX_API_URL}/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(endpoint, headers=headers, timeout=5.0)
                if resp.status_code == 200:
                    tags = [p.get('name') for p in resp.json().get('pulse_info', {}).get('pulses', [])[:3]]
                    if self.redis_client:
                        self.redis_client.setex(cache_key, timedelta(hours=12), json.dumps(tags))
                    return tags
        except Exception as e:
            logger.error(f"OTX Error: {e}")
        return []

    def check_local_heuristics(self, domain: str) -> Dict:
        """Fast local checks for known bad patterns"""
        domain = domain.lower()
        score = 0
        tags = []

        for tld in self.malicious_tlds:
            if domain.endswith(tld):
                score += 20
                tags.append(f"RiskTLD:{tld}")
                break

        for kw in self.malicious_keywords:
            if kw in domain:
                score += 25
                tags.append(f"SuspiciousKW:{kw}")

        return {"score": score, "tags": tags}

    async def enrich_query(self, domain: str, source_ip: str) -> Dict:
        """Full Multi-Source Intelligence Orchestration"""
        # Execute API calls concurrently to minimize latency
        vt_task = asyncio.create_task(self.get_vt_reputation(domain, "domain"))
        abuse_task = asyncio.create_task(self.get_abuseipdb_score(source_ip))
        otx_task = asyncio.create_task(self.get_otx_indicators(domain))

        vt_res, abuse_score, otx_tags = await asyncio.gather(vt_task, abuse_task, otx_task)
        local_intel = self.check_local_heuristics(domain)

        # Scoring Logic
        sources = ["Local Engine"]
        total_score = local_intel['score']
        threat_tags = local_intel['tags']

        if vt_res.get('malicious', 0) > 0:
            total_score += 40
            sources.append("VirusTotal")
            threat_tags.append("vt_malicious")

        if abuse_score and abuse_score > 50:
            total_score += 35
            sources.append("AbuseIPDB")
            threat_tags.append("abuseipdb_high_risk")

        if otx_tags:
            total_score += 30
            sources.append("AlienVault OTX")
            threat_tags.extend(otx_tags)

        # High Confidence Flag
        is_malicious = total_score > 50 or "vt_malicious" in threat_tags

        return {
            "domain": domain,
            "ip": source_ip,
            "reputation_score": min(total_score, 100),
            "sources": sources,
            "is_malicious": is_malicious,
            "threat_tags": list(set(threat_tags)),
            "api_stats": {
                "vt_hits": vt_res.get('malicious', 0),
                "abuse_confidence": abuse_score
            }
        }

# Singleton Service
intel_service = IntelService()
