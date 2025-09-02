"""
Live Alert and Notification System
Provides real-time alerting, notifications, and incident response automation
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import json
import threading
import queue
from enum import Enum

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertType(Enum):
    """Types of alerts"""
    THREAT_DETECTED = "threat_detected"
    IOC_MATCH = "ioc_match"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    SYSTEM_EVENT = "system_event"
    HUNTING_RESULT = "hunting_result"
    AI_ANALYSIS = "ai_analysis"

class LiveAlertSystem:
    """Advanced live alerting and notification system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.alert_queue = queue.Queue()
        self.active_alerts = []
        self.alert_history = []
        self.alert_rules = {}
        self.notification_handlers = []
        self.is_running = False
        self.alert_thread = None
        
        # Initialize default alert rules
        self._setup_default_alert_rules()
        
        # Alert counters for dashboard
        self.alert_stats = {
            'total_alerts': 0,
            'critical_alerts': 0,
            'high_alerts': 0,
            'medium_alerts': 0,
            'low_alerts': 0,
            'last_alert_time': None
        }
    
    def _setup_default_alert_rules(self):
        """Setup default alerting rules"""
        self.alert_rules = {
            'high_severity_threat': {
                'name': 'High Severity Threat Detection',
                'description': 'Triggers on critical and high severity threats',
                'conditions': {
                    'severity': ['critical', 'high'],
                    'min_confidence': 0.7
                },
                'alert_severity': AlertSeverity.HIGH,
                'enabled': True
            },
            
            'apt_indicators': {
                'name': 'APT Activity Detection',
                'description': 'Triggers on Advanced Persistent Threat indicators',
                'conditions': {
                    'keywords': ['apt', 'advanced persistent', 'nation state', 'targeted attack'],
                    'min_confidence': 0.6
                },
                'alert_severity': AlertSeverity.CRITICAL,
                'enabled': True
            },
            
            'ransomware_detection': {
                'name': 'Ransomware Activity Alert',
                'description': 'Triggers on ransomware-related activities',
                'conditions': {
                    'keywords': ['ransomware', 'encryption', 'ransom', 'bitcoin'],
                    'min_confidence': 0.8
                },
                'alert_severity': AlertSeverity.CRITICAL,
                'enabled': True
            },
            
            'suspicious_ioc': {
                'name': 'Suspicious IOC Detection',
                'description': 'Triggers on detection of suspicious indicators',
                'conditions': {
                    'ioc_types': ['ip_address', 'domain', 'url', 'hash'],
                    'min_ioc_count': 3
                },
                'alert_severity': AlertSeverity.MEDIUM,
                'enabled': True
            },
            
            'multiple_sources': {
                'name': 'Multi-Source Threat Correlation',
                'description': 'Triggers when same threat appears across multiple sources',
                'conditions': {
                    'min_sources': 2,
                    'time_window': 3600  # 1 hour
                },
                'alert_severity': AlertSeverity.HIGH,
                'enabled': True
            }
        }
    
    def start_alert_system(self):
        """Start the live alert monitoring system"""
        if self.is_running:
            return
        
        self.is_running = True
        self.alert_thread = threading.Thread(target=self._alert_processor, daemon=True)
        self.alert_thread.start()
        self.logger.info("Live alert system started")
    
    def stop_alert_system(self):
        """Stop the alert monitoring system"""
        self.is_running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=5)
        self.logger.info("Live alert system stopped")
    
    def _alert_processor(self):
        """Background thread to process alerts"""
        while self.is_running:
            try:
                # Process alerts in queue
                try:
                    alert = self.alert_queue.get(timeout=1)
                    self._process_alert(alert)
                    self.alert_queue.task_done()
                except queue.Empty:
                    continue
                    
            except Exception as e:
                logger.error(f"Error in alert processor: {e}")
    
    def _process_alert(self, alert: Dict):
        """Process individual alert"""
        try:
            # Add timestamp and ID if not present
            if 'timestamp' not in alert:
                alert['timestamp'] = datetime.now().isoformat()
            if 'id' not in alert:
                alert['id'] = f"alert_{int(datetime.now().timestamp())}"
            
            # Add to active alerts
            self.active_alerts.append(alert)
            self.alert_history.append(alert)
            
            # Update statistics
            self._update_alert_stats(alert)
            
            # Send notifications
            self._send_notifications(alert)
            
            # Log alert
            severity = alert.get('severity', 'unknown')
            message = alert.get('message', 'Unknown alert')
            self.logger.info(f"Alert triggered - {severity.upper()}: {message}")
            
            # Cleanup old active alerts (keep last 50)
            if len(self.active_alerts) > 50:
                self.active_alerts = self.active_alerts[-50:]
            
            # Cleanup old alert history (keep last 500)
            if len(self.alert_history) > 500:
                self.alert_history = self.alert_history[-500:]
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def _update_alert_stats(self, alert: Dict):
        """Update alert statistics"""
        self.alert_stats['total_alerts'] += 1
        self.alert_stats['last_alert_time'] = alert['timestamp']
        
        severity = alert.get('severity', '').lower()
        if severity in ['critical']:
            self.alert_stats['critical_alerts'] += 1
        elif severity in ['high']:
            self.alert_stats['high_alerts'] += 1
        elif severity in ['medium']:
            self.alert_stats['medium_alerts'] += 1
        elif severity in ['low']:
            self.alert_stats['low_alerts'] += 1
    
    def _send_notifications(self, alert: Dict):
        """Send alert notifications to registered handlers"""
        for handler in self.notification_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in notification handler: {e}")
    
    def add_notification_handler(self, handler: Callable):
        """Add a notification handler function"""
        self.notification_handlers.append(handler)
    
    def trigger_alert(self, alert_type: AlertType, severity: AlertSeverity, 
                     message: str, details: Optional[Dict] = None):
        """Trigger a new alert"""
        alert = {
            'type': alert_type.value,
            'severity': severity.value,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now().isoformat()
        }
        
        self.alert_queue.put(alert)
    
    def check_threat_for_alerts(self, threat: Dict):
        """Check a threat against alert rules and trigger alerts if needed"""
        try:
            for rule_id, rule in self.alert_rules.items():
                if not rule.get('enabled', True):
                    continue
                
                if self._evaluate_alert_rule(threat, rule):
                    self._trigger_rule_alert(threat, rule, rule_id)
                    
        except Exception as e:
            logger.error(f"Error checking threat for alerts: {e}")
    
    def _evaluate_alert_rule(self, threat: Dict, rule: Dict) -> bool:
        """Evaluate if a threat matches an alert rule"""
        try:
            conditions = rule.get('conditions', {})
            
            # Check severity conditions
            if 'severity' in conditions:
                threat_severity = threat.get('severity', '').lower()
                if threat_severity not in [s.lower() for s in conditions['severity']]:
                    return False
            
            # Check keyword conditions
            if 'keywords' in conditions:
                threat_text = f"{threat.get('title', '')} {threat.get('description', '')}".lower()
                if not any(keyword.lower() in threat_text for keyword in conditions['keywords']):
                    return False
            
            # Check IOC conditions
            if 'ioc_types' in conditions and 'min_ioc_count' in conditions:
                iocs = threat.get('iocs', {})
                total_iocs = sum(len(ioc_list) for ioc_list in iocs.values() if isinstance(ioc_list, list))
                if total_iocs < conditions['min_ioc_count']:
                    return False
            
            # Check confidence conditions
            if 'min_confidence' in conditions:
                confidence = threat.get('confidence', 0.5)
                if confidence < conditions['min_confidence']:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating alert rule: {e}")
            return False
    
    def _trigger_rule_alert(self, threat: Dict, rule: Dict, rule_id: str):
        """Trigger an alert based on a rule match"""
        alert = {
            'type': AlertType.THREAT_DETECTED.value,
            'severity': rule.get('alert_severity', AlertSeverity.MEDIUM).value,
            'message': f"{rule['name']}: {threat.get('title', 'Unknown threat')}",
            'details': {
                'rule_id': rule_id,
                'rule_name': rule['name'],
                'threat_id': threat.get('id'),
                'threat_title': threat.get('title'),
                'threat_source': threat.get('source'),
                'threat_severity': threat.get('severity')
            },
            'timestamp': datetime.now().isoformat()
        }
        
        self.alert_queue.put(alert)
    
    def get_active_alerts(self, limit: int = 20) -> List[Dict]:
        """Get current active alerts"""
        return self.active_alerts[-limit:] if self.active_alerts else []
    
    def get_alert_statistics(self) -> Dict:
        """Get alert system statistics"""
        return self.alert_stats.copy()
    
    def get_recent_alerts(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Get recent alerts within specified time window"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            recent_alerts = []
            for alert in reversed(self.alert_history):
                try:
                    alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                    if alert_time >= cutoff_time:
                        recent_alerts.append(alert)
                        if len(recent_alerts) >= limit:
                            break
                except:
                    continue
            
            return recent_alerts
            
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def create_alert_dashboard_html(self) -> str:
        """Create HTML for alert dashboard display"""
        try:
            stats = self.get_alert_statistics()
            recent_alerts = self.get_active_alerts(limit=10)
            
            # Generate alert summary
            html = f"""
            <div style="background: linear-gradient(135deg, #1e293b, #334155); 
                       padding: 25px; border-radius: 15px; color: white; margin-bottom: 20px;">
                <h3 style="margin: 0 0 20px 0; font-size: 1.5em;">🚨 Live Alert Dashboard</h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #ef4444;">{stats['critical_alerts']}</div>
                        <div style="color: #fca5a5;">Critical</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #f97316;">{stats['high_alerts']}</div>
                        <div style="color: #fdba74;">High</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #eab308;">{stats['medium_alerts']}</div>
                        <div style="color: #fde047;">Medium</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #22c55e;">{stats['total_alerts']}</div>
                        <div style="color: #86efac;">Total</div>
                    </div>
                </div>
            </div>
            """
            
            # Recent alerts
            if recent_alerts:
                html += """
                <div style="margin-top: 20px;">
                    <h4 style="color: #1e293b; margin-bottom: 15px;">🔔 Recent Alerts</h4>
                """
                
                for alert in recent_alerts[-5:]:  # Last 5 alerts
                    severity = alert.get('severity', 'unknown')
                    severity_colors = {
                        'critical': '#dc2626',
                        'high': '#ea580c',
                        'medium': '#d97706',
                        'low': '#059669',
                        'info': '#3b82f6'
                    }
                    
                    color = severity_colors.get(severity, '#6b7280')
                    timestamp = alert.get('timestamp', '')[:19]  # Remove microseconds
                    
                    html += f"""
                    <div style="background: #f8fafc; border-left: 4px solid {color}; 
                               padding: 15px; margin-bottom: 10px; border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #1e293b;">{alert.get('message', 'Unknown alert')}</strong>
                            <span style="background: {color}; color: white; padding: 4px 8px; 
                                       border-radius: 12px; font-size: 0.8em; text-transform: uppercase;">
                                {severity}
                            </span>
                        </div>
                        <div style="color: #64748b; font-size: 0.9em; margin-top: 5px;">
                            {timestamp} • Type: {alert.get('type', 'unknown')}
                        </div>
                    </div>
                    """
                
                html += "</div>"
            else:
                html += """
                <div style="text-align: center; padding: 40px; color: #64748b;">
                    <div style="font-size: 3em; margin-bottom: 15px;">✅</div>
                    <h4>No Active Alerts</h4>
                    <p>System is monitoring and no alerts have been triggered recently.</p>
                </div>
                """
            
            return html
            
        except Exception as e:
            logger.error(f"Error creating alert dashboard HTML: {e}")
            return "<div style='color: #dc2626;'>Error loading alert dashboard</div>"
