import json
import os
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from database import DNSAuditLog, SecurityRule, Whitelist, SessionLocal
from sqlalchemy import and_

# SOAR Security Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SOAR_ORCHESTRATOR")

class ActionOrchestrator:
    """Enterprise-Grade SOAR (Security Orchestration, Automation, and Response) Layer"""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run # Safety Switch
        self.db = SessionLocal()
        self.DEFAULT_COOLDOWN_HOURS = 24
        
        # Whitelist (System-Critical Essentials)
        self._ensure_whitelist_initialized()

    def _ensure_whitelist_initialized(self):
        """Prevents accidental blocking of gateway/DNS infrastructure"""
        essentials = [
            ("127.0.0.1", "Localhost Controller"),
            ("192.168.1.1", "Network Gateway"),
            ("8.8.8.8", "Google DNS (Essential for Platform)"),
            ("1.1.1.1", "Cloudflare DNS")
        ]
        for entity, reason in essentials:
            if not self.db.query(Whitelist).filter(Whitelist.entity == entity).first():
                self.db.add(Whitelist(entity=entity, reason=reason))
        self.db.commit()

    def _is_whitelisted(self, entity: str) -> bool:
        return self.db.query(Whitelist).filter(Whitelist.entity == entity).first() is not None

    def execute_firewall_command(self, ip: str, action: str = "BLOCK") -> bool:
        """Real-world IP Enforcement via Shell/Iptables"""
        if self.dry_run:
            logger.info(f"🔍 [DRY-RUN] Executing: iptables -A INPUT -s {ip} -j DROP")
            return True

        command = []
        if action == "BLOCK":
            # Prevent double-blocking rules
            command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        elif action == "UNBLOCK":
            command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

        try:
            # Check for root before attempting
            if os.name != 'nt': # Linux Target
                subprocess.run(command, check=True, capture_output=True)
                logger.info(f"🛡️ Firewall Rule {action} applied for {ip}")
                return True
            else: # Windows Fallback (netsh)
                win_cmd = f"netsh advfirewall firewall add rule name='DNSentinel_Block_{ip}' dir=in action=block remoteip={ip}"
                if action == "UNBLOCK":
                    win_cmd = f"netsh advfirewall firewall delete rule name='DNSentinel_Block_{ip}'"
                
                subprocess.run(win_cmd, shell=True, check=True)
                return True
        except Exception as e:
            logger.error(f"❌ Firewall Automation Error: {e}")
            return False

    def sinkhole_domain(self, domain: str, action: str = "BLOCK") -> bool:
        """Simulates DNS Sinkholing by updating local resolver/hosts configuration"""
        sinkhole_ip = "127.0.0.1"
        target_file = "/etc/hosts" if os.name != "nt" else "C:\\Windows\\System32\\drivers\\etc\\hosts"
        
        entry = f"{sinkhole_ip} {domain} # DNSentinel_Sinkhole\n"
        
        try:
            if action == "BLOCK":
                with open(target_file, "a") as f:
                    f.write(entry)
                logger.info(f"🌊 Domain {domain} redirected to {sinkhole_ip}")
            else:
                with open(target_file, "r") as f:
                    lines = f.readlines()
                with open(target_file, "w") as f:
                    for line in lines:
                        if domain not in line:
                            f.write(line)
                logger.info(f"🔓 Sinkhole entry removed for {domain}")
            return True
        except Exception as e:
            logger.error(f"⚠️ Sinkhole Permission Error: {e}. (Require Admin/Root)")
            return False

    def trigger_block(self, entity: str, reason: str, rule_type: str = "IP_BLOCK", risk_score: float = 100.0) -> Dict:
        """Original simple blocking orchestrator"""
        if self._is_whitelisted(entity):
            return {"status": "DENIED", "message": f"{entity} is in MISSION-CRITICAL whitelist."}

        # 1. Update Database Persistence
        existing = self.db.query(SecurityRule).filter(and_(SecurityRule.target == entity, SecurityRule.is_active == True)).first()
        if existing:
            return {"status": "SKIPPED", "message": "Enforcement already active."}

        expires_at = datetime.utcnow() + timedelta(hours=self.DEFAULT_COOLDOWN_HOURS)
        new_rule = SecurityRule(
            target=entity, 
            rule_type=rule_type, 
            action="BLOCK", 
            reason=reason,
            risk_score=risk_score,
            expires_at=expires_at
        )
        self.db.add(new_rule)
        self.db.commit()

        # 2. Real-Time OS Enforcement
        success = False
        if rule_type == "IP_BLOCK":
            success = self.execute_firewall_command(entity, "BLOCK")
        else: # DOMAIN_SINKHOLE
            success = self.sinkhole_domain(entity, "BLOCK")

        return {
            "status": "SUCCESS" if success else "ENFORCEMENT_FAILED",
            "entity": entity,
            "type": rule_type,
            "cooldown_end": expires_at.isoformat()
        }

    def trigger_unblock(self, entity: str) -> Dict:
        """Manual or automated rule revocation"""
        rule = self.db.query(SecurityRule).filter(and_(SecurityRule.target == entity, SecurityRule.is_active == True)).first()
        if not rule:
            return {"status": "ERROR", "message": "No active rule found for entity."}

        rule.is_active = False
        self.db.commit()

        success = False
        if rule.rule_type == "IP_BLOCK":
            success = self.execute_firewall_command(entity, "UNBLOCK")
        else:
            success = self.sinkhole_domain(entity, "UNBLOCK")

        return {"status": "REMOVED" if success else "PERSISTENCE_ONLY", "entity": entity}

    def cleanup_expired_rules(self):
        """Background task for auto-unblocking expired rules"""
        expired = self.db.query(SecurityRule).filter(
            and_(SecurityRule.is_active == True, SecurityRule.expires_at < datetime.utcnow())
        ).all()
        
        count = 0
        for rule in expired:
            self.trigger_unblock(rule.target)
            count += 1
            
        if count > 0:
            logger.info(f"🧹 SOAR Cleanup: Revoked {count} expired security rules.")

    # Legacy method compatibility (with upgrade)
    def mark_false_positive(self, log_id: int):
        log = self.db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if log:
            log.is_false_positive = True
            log.prediction = "Benign"
            log.risk_score = 5.0
            self.db.commit()
            # If there was a block on this IP, unblock it
            self.trigger_unblock(log.source_ip)
            return {"status": "RETRAINING_ACK", "log_id": log_id}
        return {"status": "NOT_FOUND"}


    def generate_incident_report(self, log_id: int) -> Optional[str]:
        """Build a Markdown SOC incident report for a single audit-log record.

        Returns None when the record does not exist so the caller can 404.
        """
        log = self.db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if not log:
            return None

        ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if log.timestamp else "N/A"
        lines = [
            f"# DNSentinel Incident Report - SOC-{log.id}",
            "",
            "## 1. Summary",
            f"- **Incident ID:** SOC-{log.id}",
            f"- **Timestamp:** {ts}",
            f"- **Source IP:** {log.source_ip}",
            f"- **Query:** `{log.query}`",
            f"- **Record Type:** {log.qtype}",
            f"- **Classification:** {log.prediction}",
            f"- **Risk Score:** {log.risk_score} ({log.risk_level})",
            f"- **Priority:** {log.priority} ({log.priority_score})",
            f"- **Blocked:** {'Yes' if log.is_blocked else 'No'}",
            "",
            "## 2. Technical Analysis",
            log.explanation or "No detailed explanation recorded.",
            "",
            "## 3. MITRE ATT&CK Mapping",
        ]
        if log.mitre_data:
            for tactic, technique in log.mitre_data.items():
                if isinstance(technique, dict):
                    name = technique.get("Name", "")
                    desc = technique.get("Description", "")
                    mitigation = technique.get("Mitigation", "")
                    lines.append(f"- **{tactic} - {name}**")
                    if desc:
                        lines.append(f"  - _Detection:_ {desc}")
                    if mitigation:
                        lines.append(f"  - _Mitigation:_ {mitigation}")
                else:
                    lines.append(f"- **{tactic}:** {technique}")
        else:
            lines.append("- No MITRE techniques mapped for this event.")
        lines += [
            "",
            "## 4. Recommended Actions",
            "- Review the source endpoint for related activity.",
            "- Confirm containment (block/sinkhole) if malicious.",
            "- Mark as false positive if benign to feed the analyst feedback loop.",
            "",
            "_Generated automatically by DNSentinel SOAR._",
        ]
        return "\n".join(lines)

orchestrator = ActionOrchestrator(dry_run=True) # Default to dry-run for safety
