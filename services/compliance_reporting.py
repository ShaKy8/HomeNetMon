"""
Compliance Reporting Engine

This service provides comprehensive compliance reporting and audit capabilities:
1. Generate compliance reports for various frameworks (CIS, NIST, PCI-DSS, ISO27001)
2. Track compliance scores and trends over time
3. Create audit trails and evidence collection
4. Generate executive dashboards and detailed technical reports
5. Schedule automated compliance assessments and reporting
"""

import logging
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

from models import db, Device, ComplianceResult, SecurityVulnerability, SecurityScan, SecurityEvent
from services.security_scanner import security_scanner, ComplianceFramework

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Available report formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"


class ReportType(Enum):
    """Types of compliance reports"""
    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_TECHNICAL = "detailed_technical"
    COMPLIANCE_SCORECARD = "compliance_scorecard"
    TREND_ANALYSIS = "trend_analysis"
    AUDIT_EVIDENCE = "audit_evidence"
    REMEDIATION_PLAN = "remediation_plan"


@dataclass
class ComplianceScore:
    """Compliance scoring information"""
    framework: ComplianceFramework
    overall_score: float
    passed_checks: int
    failed_checks: int
    total_checks: int
    critical_failures: int
    high_failures: int
    compliance_percentage: float
    last_assessment: datetime
    trend_direction: str  # "improving", "stable", "declining"
    
    
@dataclass
class ComplianceReport:
    """Complete compliance report"""
    report_id: str
    framework: ComplianceFramework
    report_type: ReportType
    generated_at: datetime
    generated_by: str
    reporting_period_start: datetime
    reporting_period_end: datetime
    scope_description: str
    executive_summary: Dict[str, Any]
    detailed_findings: List[Dict[str, Any]]
    compliance_scores: Dict[str, ComplianceScore]
    recommendations: List[str]
    audit_trail: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceReportingEngine:
    """Comprehensive compliance reporting and audit system"""
    
    def __init__(self, app=None):
        self.app = app
        self.report_cache = {}
        self.scheduled_reports = []
        
        # Reporting configuration
        self.config = {
            'auto_generate_reports': True,
            'report_retention_days': 365,
            'schedule_daily_scorecards': True,
            'schedule_weekly_summaries': True,
            'schedule_monthly_detailed': True,
            'default_frameworks': [ComplianceFramework.CIS, ComplianceFramework.NIST]
        }
        
        # Report templates and configurations
        self.report_templates = {
            ReportType.EXECUTIVE_SUMMARY: {
                'sections': ['overview', 'key_metrics', 'top_risks', 'recommendations'],
                'max_length_pages': 5,
                'include_charts': True
            },
            ReportType.DETAILED_TECHNICAL: {
                'sections': ['methodology', 'detailed_findings', 'evidence', 'technical_details'],
                'max_length_pages': 50,
                'include_raw_data': True
            },
            ReportType.COMPLIANCE_SCORECARD: {
                'sections': ['scores_by_framework', 'trends', 'comparisons'],
                'max_length_pages': 3,
                'include_charts': True
            }
        }
        
        # Compliance scoring weights
        self.scoring_weights = {
            'critical_failure': -10,
            'high_failure': -5,
            'medium_failure': -2,
            'low_failure': -1,
            'pass': 1,
            'not_applicable': 0
        }
        
    def start_reporting_scheduler(self):
        """Start the automated reporting scheduler"""
        if not self.config['auto_generate_reports']:
            return
        
        scheduler_thread = threading.Thread(
            target=self._reporting_scheduler_loop,
            daemon=True,
            name='ComplianceReportingScheduler'
        )
        scheduler_thread.start()
        
        logger.info("Compliance reporting scheduler started")
    
    def _reporting_scheduler_loop(self):
        """Main scheduler loop for automated report generation"""
        while True:
            try:
                current_time = datetime.utcnow()
                
                # Check for scheduled reports
                if self.config['schedule_daily_scorecards'] and current_time.hour == 6:  # 6 AM daily
                    self._schedule_daily_scorecard()
                
                if self.config['schedule_weekly_summaries'] and current_time.weekday() == 0 and current_time.hour == 7:  # Monday 7 AM
                    self._schedule_weekly_summary()
                
                if self.config['schedule_monthly_detailed'] and current_time.day == 1 and current_time.hour == 8:  # 1st of month 8 AM
                    self._schedule_monthly_detailed_report()
                
                # Process scheduled reports
                self._process_scheduled_reports()
                
                # Clean up old reports
                self._cleanup_old_reports()
                
                time.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in reporting scheduler loop: {e}")
                time.sleep(3600)
    
    def generate_compliance_report(self, 
                                 framework: ComplianceFramework,
                                 report_type: ReportType,
                                 period_days: int = 30,
                                 scope_filter: Optional[Dict[str, Any]] = None) -> ComplianceReport:
        """Generate a comprehensive compliance report"""
        try:
            logger.info(f"Generating {report_type.value} report for {framework.value}")
            
            current_time = datetime.utcnow()
            period_start = current_time - timedelta(days=period_days)
            
            report_id = f"{framework.value}_{report_type.value}_{int(current_time.timestamp())}"
            
            # Gather compliance data
            compliance_data = self._gather_compliance_data(framework, period_start, current_time, scope_filter)
            
            # Calculate compliance scores
            compliance_scores = self._calculate_compliance_scores(compliance_data)
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(compliance_data, compliance_scores)
            
            # Generate detailed findings
            detailed_findings = self._generate_detailed_findings(compliance_data, report_type)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(compliance_data, compliance_scores)
            
            # Build audit trail
            audit_trail = self._build_audit_trail(compliance_data)
            
            # Create the report
            report = ComplianceReport(
                report_id=report_id,
                framework=framework,
                report_type=report_type,
                generated_at=current_time,
                generated_by="HomeNetMon Compliance Engine",
                reporting_period_start=period_start,
                reporting_period_end=current_time,
                scope_description=self._build_scope_description(scope_filter),
                executive_summary=executive_summary,
                detailed_findings=detailed_findings,
                compliance_scores={framework.value: compliance_scores},
                recommendations=recommendations,
                audit_trail=audit_trail,
                metadata={
                    'total_devices_assessed': compliance_data.get('device_count', 0),
                    'total_checks_performed': compliance_data.get('total_checks', 0),
                    'assessment_duration_days': period_days,
                    'report_version': '1.0'
                }
            )
            
            # Cache the report
            self.report_cache[report_id] = report
            
            logger.info(f"Generated compliance report {report_id}")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            raise
    
    def _gather_compliance_data(self, 
                               framework: ComplianceFramework,
                               start_time: datetime,
                               end_time: datetime,
                               scope_filter: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Gather all relevant compliance data for the reporting period"""
        try:
            if not self.app:
                return {}
            
            with self.app.app_context():
                # Get compliance results for the framework and period
                compliance_query = ComplianceResult.query.filter(
                    ComplianceResult.framework == framework.value,
                    ComplianceResult.checked_at >= start_time,
                    ComplianceResult.checked_at <= end_time
                )
                
                compliance_results = compliance_query.all()
                
                # Get security vulnerabilities for context
                vulnerabilities = SecurityVulnerability.query.filter(
                    SecurityVulnerability.discovered_at >= start_time,
                    SecurityVulnerability.discovered_at <= end_time
                ).all()
                
                # Get security scan results
                security_scans = SecurityScan.query.filter(
                    SecurityScan.scanned_at >= start_time,
                    SecurityScan.scanned_at <= end_time
                ).all()
                
                # Get security events
                security_events = SecurityEvent.query.filter(
                    SecurityEvent.created_at >= start_time,
                    SecurityEvent.created_at <= end_time
                ).all()
                
                # Get device information
                devices = Device.query.filter_by(is_monitored=True).all()
                
                # Organize the data
                data = {
                    'framework': framework.value,
                    'reporting_period': {
                        'start': start_time.isoformat(),
                        'end': end_time.isoformat(),
                        'days': (end_time - start_time).days
                    },
                    'compliance_results': [self._serialize_compliance_result(r) for r in compliance_results],
                    'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                    'security_scans': [self._serialize_security_scan(s) for s in security_scans],
                    'security_events': [self._serialize_security_event(e) for e in security_events],
                    'devices': [self._serialize_device(d) for d in devices],
                    'device_count': len(devices),
                    'total_checks': len(compliance_results)
                }
                
                return data
                
        except Exception as e:
            logger.error(f"Error gathering compliance data: {e}")
            return {}
    
    def _calculate_compliance_scores(self, compliance_data: Dict[str, Any]) -> ComplianceScore:
        """Calculate comprehensive compliance scores"""
        try:
            compliance_results = compliance_data.get('compliance_results', [])
            
            if not compliance_results:
                return ComplianceScore(
                    framework=ComplianceFramework(compliance_data.get('framework', 'cis')),
                    overall_score=0.0,
                    passed_checks=0,
                    failed_checks=0,
                    total_checks=0,
                    critical_failures=0,
                    high_failures=0,
                    compliance_percentage=0.0,
                    last_assessment=datetime.utcnow(),
                    trend_direction="stable"
                )
            
            # Count results by status and severity
            status_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for result in compliance_results:
                status_counts[result['status']] += 1
                severity_counts[result['severity']] += 1
            
            total_checks = len(compliance_results)
            passed_checks = status_counts['pass']
            failed_checks = status_counts['fail']
            
            # Calculate weighted score
            score = 0.0
            for result in compliance_results:
                status = result['status']
                severity = result['severity']
                
                if status == 'pass':
                    score += self.scoring_weights['pass']
                elif status == 'fail':
                    if severity == 'critical':
                        score += self.scoring_weights['critical_failure']
                    elif severity == 'high':
                        score += self.scoring_weights['high_failure']
                    elif severity == 'medium':
                        score += self.scoring_weights['medium_failure']
                    else:
                        score += self.scoring_weights['low_failure']
                else:  # not_applicable
                    score += self.scoring_weights['not_applicable']
            
            # Normalize score to 0-100 scale
            max_possible_score = total_checks * self.scoring_weights['pass']
            overall_score = max(0, min(100, (score / max_possible_score) * 100)) if max_possible_score > 0 else 0
            
            compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
            
            # Determine trend (would need historical data for accurate trend)
            trend_direction = self._determine_compliance_trend(compliance_data['framework'], overall_score)
            
            return ComplianceScore(
                framework=ComplianceFramework(compliance_data['framework']),
                overall_score=round(overall_score, 1),
                passed_checks=passed_checks,
                failed_checks=failed_checks,
                total_checks=total_checks,
                critical_failures=severity_counts['critical'],
                high_failures=severity_counts['high'],
                compliance_percentage=round(compliance_percentage, 1),
                last_assessment=datetime.utcnow(),
                trend_direction=trend_direction
            )
            
        except Exception as e:
            logger.error(f"Error calculating compliance scores: {e}")
            return ComplianceScore(
                framework=ComplianceFramework.CIS,
                overall_score=0.0,
                passed_checks=0,
                failed_checks=0,
                total_checks=0,
                critical_failures=0,
                high_failures=0,
                compliance_percentage=0.0,
                last_assessment=datetime.utcnow(),
                trend_direction="stable"
            )
    
    def _generate_executive_summary(self, 
                                  compliance_data: Dict[str, Any], 
                                  scores: ComplianceScore) -> Dict[str, Any]:
        """Generate executive summary section of the report"""
        try:
            summary = {
                'report_overview': {
                    'framework': compliance_data['framework'].upper(),
                    'assessment_period': f"{scores.last_assessment.strftime('%Y-%m-%d')}",
                    'devices_assessed': compliance_data.get('device_count', 0),
                    'checks_performed': compliance_data.get('total_checks', 0)
                },
                'key_metrics': {
                    'overall_compliance_score': scores.overall_score,
                    'compliance_percentage': scores.compliance_percentage,
                    'total_passed': scores.passed_checks,
                    'total_failed': scores.failed_checks,
                    'critical_issues': scores.critical_failures,
                    'high_priority_issues': scores.high_failures,
                    'trend': scores.trend_direction
                },
                'risk_assessment': self._assess_overall_risk(compliance_data, scores),
                'top_priorities': self._identify_top_priorities(compliance_data, scores)
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {}
    
    def _generate_detailed_findings(self, 
                                  compliance_data: Dict[str, Any],
                                  report_type: ReportType) -> List[Dict[str, Any]]:
        """Generate detailed findings section"""
        try:
            findings = []
            
            compliance_results = compliance_data.get('compliance_results', [])
            
            # Group findings by category/control area
            findings_by_category = defaultdict(list)
            
            for result in compliance_results:
                category = self._extract_category_from_rule_id(result['rule_id'])
                findings_by_category[category].append(result)
            
            # Generate detailed findings for each category
            for category, category_results in findings_by_category.items():
                failed_results = [r for r in category_results if r['status'] == 'fail']
                passed_results = [r for r in category_results if r['status'] == 'pass']
                
                finding = {
                    'category': category,
                    'category_score': (len(passed_results) / len(category_results) * 100) if category_results else 0,
                    'total_controls': len(category_results),
                    'passed_controls': len(passed_results),
                    'failed_controls': len(failed_results),
                    'critical_failures': len([r for r in failed_results if r['severity'] == 'critical']),
                    'high_failures': len([r for r in failed_results if r['severity'] == 'high']),
                    'failed_controls_detail': failed_results if report_type == ReportType.DETAILED_TECHNICAL else failed_results[:10],
                    'remediation_summary': self._generate_category_remediation(failed_results)
                }
                
                findings.append(finding)
            
            # Sort by severity (most critical first)
            findings.sort(key=lambda x: (x['critical_failures'], x['high_failures']), reverse=True)
            
            return findings
            
        except Exception as e:\n            logger.error(f"Error generating detailed findings: {e}")
            return []
    
    def _generate_recommendations(self, 
                                compliance_data: Dict[str, Any],
                                scores: ComplianceScore) -> List[str]:
        """Generate actionable recommendations"""
        try:
            recommendations = []
            
            # Priority-based recommendations
            if scores.critical_failures > 0:
                recommendations.append(f"IMMEDIATE ACTION REQUIRED: Address {scores.critical_failures} critical compliance failures")
                recommendations.append("Consider implementing emergency security measures until critical issues are resolved")
            
            if scores.high_failures > 5:
                recommendations.append(f"HIGH PRIORITY: Resolve {scores.high_failures} high-severity compliance issues")
            
            # Compliance percentage based recommendations
            if scores.compliance_percentage < 70:
                recommendations.append("Overall compliance is below acceptable threshold (70%). Implement comprehensive remediation plan")
                recommendations.append("Consider engaging security consultants for compliance gap analysis")
            elif scores.compliance_percentage < 85:
                recommendations.append("Focus on addressing remaining compliance gaps to achieve industry best practices (85%+)")
            
            # Trend-based recommendations
            if scores.trend_direction == "declining":
                recommendations.append("Compliance trend is declining. Review and strengthen compliance monitoring processes")
            elif scores.trend_direction == "stable" and scores.compliance_percentage < 90:
                recommendations.append("Implement continuous improvement processes to enhance compliance posture")
            
            # Framework-specific recommendations
            framework_recommendations = self._get_framework_specific_recommendations(compliance_data['framework'], scores)
            recommendations.extend(framework_recommendations)
            
            # Vulnerability-based recommendations
            vulnerabilities = compliance_data.get('vulnerabilities', [])
            if vulnerabilities:
                high_risk_vulns = [v for v in vulnerabilities if v['risk_score'] >= 7.0]
                if high_risk_vulns:
                    recommendations.append(f"Address {len(high_risk_vulns)} high-risk security vulnerabilities that may impact compliance")
            
            return recommendations[:10]  # Limit to top 10 recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return ["Review compliance assessment results and implement necessary security improvements"]
    
    def _build_audit_trail(self, compliance_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build comprehensive audit trail"""
        try:
            audit_trail = []
            
            # Add compliance assessments to audit trail
            for result in compliance_data.get('compliance_results', []):
                audit_trail.append({
                    'timestamp': result['checked_at'],
                    'event_type': 'compliance_check',
                    'framework': compliance_data['framework'],
                    'rule_id': result['rule_id'],
                    'result': result['status'],
                    'severity': result['severity'],
                    'evidence': result.get('evidence', {}),
                    'automated': True
                })
            
            # Add security events to audit trail
            for event in compliance_data.get('security_events', []):
                audit_trail.append({
                    'timestamp': event['created_at'],
                    'event_type': 'security_event',
                    'event_subtype': event['event_type'],
                    'severity': event['severity'],
                    'message': event['message'],
                    'device_id': event.get('device_id'),
                    'automated': True
                })
            
            # Sort by timestamp
            audit_trail.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return audit_trail[:100]  # Limit to 100 most recent events
            
        except Exception as e:
            logger.error(f"Error building audit trail: {e}")
            return []
    
    def export_report(self, report: ComplianceReport, format: ReportFormat, file_path: Optional[str] = None) -> str:
        """Export compliance report in specified format"""
        try:
            if format == ReportFormat.JSON:
                return self._export_json_report(report, file_path)
            elif format == ReportFormat.HTML:
                return self._export_html_report(report, file_path)
            elif format == ReportFormat.CSV:
                return self._export_csv_report(report, file_path)
            else:
                raise ValueError(f"Unsupported report format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
            raise
    
    def _export_json_report(self, report: ComplianceReport, file_path: Optional[str]) -> str:
        """Export report as JSON"""
        try:
            report_dict = {
                'report_id': report.report_id,
                'framework': report.framework.value,
                'report_type': report.report_type.value,
                'generated_at': report.generated_at.isoformat(),
                'generated_by': report.generated_by,
                'reporting_period': {
                    'start': report.reporting_period_start.isoformat(),
                    'end': report.reporting_period_end.isoformat()
                },
                'scope_description': report.scope_description,
                'executive_summary': report.executive_summary,
                'detailed_findings': report.detailed_findings,
                'compliance_scores': {
                    k: {
                        'framework': v.framework.value,
                        'overall_score': v.overall_score,
                        'passed_checks': v.passed_checks,
                        'failed_checks': v.failed_checks,
                        'total_checks': v.total_checks,
                        'critical_failures': v.critical_failures,
                        'high_failures': v.high_failures,
                        'compliance_percentage': v.compliance_percentage,
                        'last_assessment': v.last_assessment.isoformat(),
                        'trend_direction': v.trend_direction
                    } for k, v in report.compliance_scores.items()
                },
                'recommendations': report.recommendations,
                'audit_trail': report.audit_trail,
                'metadata': report.metadata
            }
            
            json_content = json.dumps(report_dict, indent=2, default=str)
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(json_content)
                return file_path
            else:
                return json_content
                
        except Exception as e:
            logger.error(f"Error exporting JSON report: {e}")
            raise
    
    def get_compliance_trends(self, framework: ComplianceFramework, days: int = 90) -> Dict[str, Any]:
        """Get compliance trends over time"""
        try:
            if not self.app:
                return {}
            
            with self.app.app_context():
                end_date = datetime.utcnow()
                start_date = end_date - timedelta(days=days)
                
                # Get compliance results over time
                results = ComplianceResult.query.filter(
                    ComplianceResult.framework == framework.value,
                    ComplianceResult.checked_at >= start_date,
                    ComplianceResult.checked_at <= end_date
                ).order_by(ComplianceResult.checked_at).all()
                
                # Group by date and calculate daily scores
                daily_scores = defaultdict(lambda: {'passed': 0, 'failed': 0, 'total': 0})
                
                for result in results:
                    date_key = result.checked_at.date().isoformat()
                    daily_scores[date_key]['total'] += 1
                    if result.status == 'pass':
                        daily_scores[date_key]['passed'] += 1
                    elif result.status == 'fail':
                        daily_scores[date_key]['failed'] += 1
                
                # Convert to trend data
                trend_data = []
                for date_str, scores in sorted(daily_scores.items()):
                    compliance_pct = (scores['passed'] / scores['total'] * 100) if scores['total'] > 0 else 0
                    trend_data.append({
                        'date': date_str,
                        'compliance_percentage': round(compliance_pct, 1),
                        'passed_checks': scores['passed'],
                        'failed_checks': scores['failed'],
                        'total_checks': scores['total']
                    })
                
                return {
                    'framework': framework.value,
                    'period_days': days,
                    'trend_data': trend_data,
                    'summary': {
                        'total_assessments': len(results),
                        'average_compliance': round(sum(d['compliance_percentage'] for d in trend_data) / len(trend_data), 1) if trend_data else 0,
                        'trend_direction': self._calculate_trend_direction(trend_data)
                    }
                }
                
        except Exception as e:
            logger.error(f"Error getting compliance trends: {e}")
            return {}
    
    # Helper methods
    def _serialize_compliance_result(self, result: ComplianceResult) -> Dict[str, Any]:
        """Serialize compliance result for reporting"""
        return {
            'id': result.id,
            'check_id': result.check_id,
            'rule_id': result.rule_id,
            'title': result.title,
            'description': result.description,
            'severity': result.severity,
            'status': result.status,
            'evidence': result.evidence,
            'remediation': result.remediation,
            'checked_at': result.checked_at.isoformat()
        }
    
    def _serialize_security_scan(self, scan: SecurityScan) -> Dict[str, Any]:
        """Serialize security scan for reporting"""
        return {
            'id': scan.id,
            'device_id': scan.device_id,
            'ip_address': scan.ip_address,
            'port': scan.port,
            'state': scan.state,
            'service': scan.service,
            'version': scan.version,
            'risk_score': scan.risk_score,
            'scanned_at': scan.scanned_at.isoformat()
        }
    
    def _serialize_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Serialize security event for reporting"""
        return {
            'id': event.id,
            'device_id': event.device_id,
            'event_type': event.event_type,
            'severity': event.severity,
            'message': event.message,
            'metadata': event.event_metadata,
            'created_at': event.created_at.isoformat()
        }
    
    def _serialize_device(self, device: Device) -> Dict[str, Any]:
        """Serialize device for reporting"""
        return {
            'id': device.id,
            'ip_address': device.ip_address,
            'hostname': device.hostname,
            'device_type': device.device_type,
            'vendor': device.vendor,
            'status': device.status,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None
        }
    
    def _build_scope_description(self, scope_filter: Optional[Dict[str, Any]]) -> str:
        """Build description of report scope"""
        if not scope_filter:
            return "All monitored devices and network infrastructure"
        
        descriptions = []
        if 'device_types' in scope_filter:
            descriptions.append(f"Device types: {', '.join(scope_filter['device_types'])}")
        if 'ip_ranges' in scope_filter:
            descriptions.append(f"IP ranges: {', '.join(scope_filter['ip_ranges'])}")
        if 'severity_levels' in scope_filter:
            descriptions.append(f"Severity levels: {', '.join(scope_filter['severity_levels'])}")
        
        return "; ".join(descriptions) if descriptions else "Custom scope filter applied"
    
    def _determine_compliance_trend(self, framework: str, current_score: float) -> str:
        """Determine compliance trend direction"""
        # In production, this would compare with historical data
        # For now, return stable as default
        return "stable"
    
    def _assess_overall_risk(self, compliance_data: Dict[str, Any], scores: ComplianceScore) -> Dict[str, Any]:
        """Assess overall organizational risk based on compliance data"""
        try:
            vulnerabilities = compliance_data.get('vulnerabilities', [])
            high_risk_vulns = len([v for v in vulnerabilities if v['risk_score'] >= 7.0])
            
            # Risk level calculation
            if scores.critical_failures > 0 or high_risk_vulns > 10:
                risk_level = "CRITICAL"
                risk_score = 9
            elif scores.high_failures > 5 or high_risk_vulns > 5:
                risk_level = "HIGH"
                risk_score = 7
            elif scores.compliance_percentage < 70:
                risk_level = "MEDIUM"
                risk_score = 5
            elif scores.compliance_percentage < 85:
                risk_level = "LOW"
                risk_score = 3
            else:
                risk_level = "MINIMAL"
                risk_score = 1
            
            return {
                'risk_level': risk_level,
                'risk_score': risk_score,
                'primary_risk_factors': self._identify_primary_risk_factors(compliance_data, scores),
                'business_impact_assessment': self._assess_business_impact(risk_level),
                'recommended_actions': self._get_risk_based_actions(risk_level)
            }
            
        except Exception as e:
            logger.error(f"Error assessing overall risk: {e}")
            return {'risk_level': 'UNKNOWN', 'risk_score': 5}
    
    def _identify_primary_risk_factors(self, compliance_data: Dict[str, Any], scores: ComplianceScore) -> List[str]:
        """Identify primary risk factors"""
        risk_factors = []
        
        if scores.critical_failures > 0:
            risk_factors.append(f"Critical compliance failures ({scores.critical_failures})")
        
        if scores.high_failures > 5:
            risk_factors.append(f"Multiple high-severity compliance issues ({scores.high_failures})")
        
        vulnerabilities = compliance_data.get('vulnerabilities', [])
        critical_vulns = len([v for v in vulnerabilities if v['severity'] == 'critical'])
        if critical_vulns > 0:
            risk_factors.append(f"Critical security vulnerabilities ({critical_vulns})")
        
        if scores.compliance_percentage < 70:
            risk_factors.append(f"Below-threshold compliance rate ({scores.compliance_percentage}%)")
        
        return risk_factors[:5]  # Top 5 risk factors
    
    def _assess_business_impact(self, risk_level: str) -> str:
        """Assess business impact based on risk level"""
        impact_descriptions = {
            'CRITICAL': 'Immediate threat to business operations and regulatory compliance',
            'HIGH': 'Significant risk to business continuity and potential regulatory penalties',
            'MEDIUM': 'Moderate risk that could impact business operations if unaddressed',
            'LOW': 'Limited business impact but requires attention for best practices',
            'MINIMAL': 'Low business impact with good security posture maintained'
        }
        return impact_descriptions.get(risk_level, 'Unknown business impact')
    
    def _get_risk_based_actions(self, risk_level: str) -> List[str]:
        """Get recommended actions based on risk level"""
        action_map = {
            'CRITICAL': [
                'Implement emergency security measures immediately',
                'Consider engaging external security consultants',
                'Notify executive leadership and board of directors',
                'Activate incident response procedures'
            ],
            'HIGH': [
                'Prioritize high-severity issues in next sprint',
                'Increase security monitoring and alerting',
                'Review and update security policies',
                'Conduct security awareness training'
            ],
            'MEDIUM': [
                'Develop remediation plan with timeline',
                'Review security controls and procedures',
                'Implement additional monitoring where needed',
                'Schedule regular compliance assessments'
            ],
            'LOW': [
                'Address remaining compliance gaps gradually',
                'Maintain current security practices',
                'Continue regular monitoring and assessment',
                'Document current security posture'
            ],
            'MINIMAL': [
                'Maintain excellent security posture',
                'Continue regular assessments and monitoring',
                'Share best practices with industry peers',
                'Consider advanced security certifications'
            ]
        }
        return action_map.get(risk_level, ['Review current security posture'])
    
    def _identify_top_priorities(self, compliance_data: Dict[str, Any], scores: ComplianceScore) -> List[Dict[str, Any]]:
        """Identify top priority items for immediate attention"""
        try:
            priorities = []
            
            compliance_results = compliance_data.get('compliance_results', [])
            
            # Critical failures
            critical_failures = [r for r in compliance_results if r['status'] == 'fail' and r['severity'] == 'critical']
            for failure in critical_failures[:3]:  # Top 3 critical
                priorities.append({
                    'priority': 'CRITICAL',
                    'title': failure['title'],
                    'description': failure['description'],
                    'rule_id': failure['rule_id'],
                    'impact': 'Immediate security risk'
                })
            
            # High-impact vulnerabilities
            vulnerabilities = compliance_data.get('vulnerabilities', [])
            high_risk_vulns = sorted([v for v in vulnerabilities if v['risk_score'] >= 8.0], 
                                   key=lambda x: x['risk_score'], reverse=True)
            
            for vuln in high_risk_vulns[:2]:  # Top 2 high-risk vulnerabilities
                priorities.append({
                    'priority': 'HIGH',
                    'title': vuln['title'],
                    'description': vuln['description'],
                    'device': vuln['device_name'],
                    'impact': 'Security vulnerability requiring immediate attention'
                })
            
            return priorities[:5]  # Top 5 priorities
            
        except Exception as e:
            logger.error(f"Error identifying top priorities: {e}")
            return []
    
    def _extract_category_from_rule_id(self, rule_id: str) -> str:
        """Extract category/control area from rule ID"""
        # Simple categorization based on rule ID patterns
        if rule_id.startswith('CIS'):
            # CIS Controls categorization
            if '2.' in rule_id:
                return 'Inventory and Control of Software Assets'
            elif '3.' in rule_id:
                return 'Continuous Vulnerability Management'
            elif '4.' in rule_id:
                return 'Controlled Use of Administrative Privileges'
            elif '5.' in rule_id:
                return 'Secure Configuration Management'
            elif '6.' in rule_id:
                return 'Maintenance, Monitoring and Analysis of Audit Logs'
            else:
                return 'General Controls'
        elif rule_id.startswith('NIST'):
            # NIST Framework categorization
            if 'ID.' in rule_id:
                return 'Identify'
            elif 'PR.' in rule_id:
                return 'Protect'
            elif 'DE.' in rule_id:
                return 'Detect'
            elif 'RS.' in rule_id:
                return 'Respond'
            elif 'RC.' in rule_id:
                return 'Recover'
            else:
                return 'General Framework'
        else:
            return 'Miscellaneous Controls'
    
    def _generate_category_remediation(self, failed_results: List[Dict[str, Any]]) -> List[str]:
        """Generate remediation summary for a category"""
        if not failed_results:
            return []
        
        # Extract common remediation themes
        all_remediation = []
        for result in failed_results:
            remediation = result.get('remediation', [])
            if isinstance(remediation, list):
                all_remediation.extend(remediation)
        
        # Find most common remediation actions
        remediation_counts = defaultdict(int)
        for action in all_remediation:
            remediation_counts[action] += 1
        
        # Return top remediation actions
        top_actions = sorted(remediation_counts.items(), key=lambda x: x[1], reverse=True)
        return [action for action, count in top_actions[:5]]
    
    def _get_framework_specific_recommendations(self, framework: str, scores: ComplianceScore) -> List[str]:
        """Get framework-specific recommendations"""
        recommendations = []
        
        if framework == 'cis':
            if scores.compliance_percentage < 80:
                recommendations.append("Focus on CIS Critical Security Controls implementation")
                recommendations.append("Prioritize Basic and Foundational controls before Advanced controls")
        elif framework == 'nist':
            if scores.compliance_percentage < 75:
                recommendations.append("Strengthen NIST Cybersecurity Framework implementation across all functions")
                recommendations.append("Focus on Identify and Protect functions as foundation")
        elif framework == 'pci_dss':
            if scores.critical_failures > 0:
                recommendations.append("Address PCI DSS compliance gaps immediately to avoid payment card industry penalties")
        
        return recommendations
    
    def _calculate_trend_direction(self, trend_data: List[Dict[str, Any]]) -> str:
        """Calculate overall trend direction from trend data"""
        if len(trend_data) < 2:
            return "stable"
        
        # Simple linear trend calculation
        recent_scores = [d['compliance_percentage'] for d in trend_data[-5:]]  # Last 5 data points
        early_scores = [d['compliance_percentage'] for d in trend_data[:5]]   # First 5 data points
        
        if len(recent_scores) < 2 or len(early_scores) < 2:
            return "stable"
        
        recent_avg = sum(recent_scores) / len(recent_scores)
        early_avg = sum(early_scores) / len(early_scores)
        
        diff_threshold = 5  # 5% threshold for trend detection
        
        if recent_avg > early_avg + diff_threshold:
            return "improving"
        elif recent_avg < early_avg - diff_threshold:
            return "declining"
        else:
            return "stable"
    
    def _export_html_report(self, report: ComplianceReport, file_path: Optional[str]) -> str:
        """Export report as HTML (basic implementation)"""
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Compliance Report - {report.framework.value.upper()}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                    .section {{ margin: 20px 0; }}
                    .metric {{ display: inline-block; margin: 10px; padding: 15px; background-color: #e9ecef; border-radius: 5px; }}
                    .critical {{ color: #dc3545; font-weight: bold; }}
                    .high {{ color: #fd7e14; font-weight: bold; }}
                    .medium {{ color: #ffc107; }}
                    .low {{ color: #28a745; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Compliance Report</h1>
                    <h2>Framework: {report.framework.value.upper()}</h2>
                    <p>Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>Report ID: {report.report_id}</p>
                </div>
                
                <div class="section">
                    <h3>Executive Summary</h3>
                    <div class="metric">
                        Compliance Score: <strong>{report.compliance_scores.get(report.framework.value, type('obj', (object,), {'overall_score': 0})).overall_score}%</strong>
                    </div>
                    <div class="metric">
                        Compliance Rate: <strong>{report.compliance_scores.get(report.framework.value, type('obj', (object,), {'compliance_percentage': 0})).compliance_percentage}%</strong>
                    </div>
                    <div class="metric">
                        Critical Issues: <span class="critical">{report.compliance_scores.get(report.framework.value, type('obj', (object,), {'critical_failures': 0})).critical_failures}</span>
                    </div>
                </div>
                
                <div class="section">
                    <h3>Recommendations</h3>
                    <ul>
                        {''.join(f'<li>{rec}</li>' for rec in report.recommendations)}
                    </ul>
                </div>
                
                <div class="section">
                    <h3>Detailed Findings</h3>
                    {''.join(f'<h4>{finding["category"]}</h4><p>Score: {finding["category_score"]:.1f}% | Failed: {finding["failed_controls"]} | Critical: {finding["critical_failures"]}</p>' for finding in report.detailed_findings)}
                </div>
            </body>
            </html>
            """
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(html_content)
                return file_path
            else:
                return html_content
                
        except Exception as e:
            logger.error(f"Error exporting HTML report: {e}")
            raise
    
    def _export_csv_report(self, report: ComplianceReport, file_path: Optional[str]) -> str:
        """Export report as CSV (basic implementation)"""
        try:
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Report Information'])
            writer.writerow(['Report ID', report.report_id])
            writer.writerow(['Framework', report.framework.value])
            writer.writerow(['Generated', report.generated_at.isoformat()])
            writer.writerow([])
            
            # Write compliance scores
            writer.writerow(['Compliance Metrics'])
            for framework, scores in report.compliance_scores.items():
                writer.writerow(['Framework', framework])
                writer.writerow(['Overall Score', scores.overall_score])
                writer.writerow(['Compliance Percentage', scores.compliance_percentage])
                writer.writerow(['Passed Checks', scores.passed_checks])
                writer.writerow(['Failed Checks', scores.failed_checks])
                writer.writerow(['Critical Failures', scores.critical_failures])
                writer.writerow(['High Failures', scores.high_failures])
            writer.writerow([])
            
            # Write detailed findings
            writer.writerow(['Detailed Findings'])
            writer.writerow(['Category', 'Score', 'Total Controls', 'Failed Controls', 'Critical Failures', 'High Failures'])
            for finding in report.detailed_findings:
                writer.writerow([
                    finding['category'],
                    f"{finding['category_score']:.1f}%",
                    finding['total_controls'],
                    finding['failed_controls'],
                    finding['critical_failures'],
                    finding['high_failures']
                ])
            
            csv_content = output.getvalue()
            output.close()
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(csv_content)
                return file_path
            else:
                return csv_content
                
        except Exception as e:
            logger.error(f"Error exporting CSV report: {e}")
            raise
    
    def _schedule_daily_scorecard(self):
        """Schedule daily compliance scorecard generation"""
        logger.info("Scheduling daily compliance scorecard")
        # Implementation would add to scheduled reports queue
    
    def _schedule_weekly_summary(self):
        """Schedule weekly compliance summary"""
        logger.info("Scheduling weekly compliance summary")
        # Implementation would add to scheduled reports queue
    
    def _schedule_monthly_detailed_report(self):
        """Schedule monthly detailed compliance report"""
        logger.info("Scheduling monthly detailed compliance report")
        # Implementation would add to scheduled reports queue
    
    def _process_scheduled_reports(self):
        """Process any scheduled reports"""
        # Implementation would process scheduled report queue
        pass
    
    def _cleanup_old_reports(self):
        """Clean up old reports based on retention policy"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.config['report_retention_days'])
            
            # Remove old reports from cache
            to_remove = []
            for report_id, report in self.report_cache.items():
                if report.generated_at < cutoff_date:
                    to_remove.append(report_id)
            
            for report_id in to_remove:
                del self.report_cache[report_id]
            
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} old reports from cache")
                
        except Exception as e:
            logger.error(f"Error cleaning up old reports: {e}")


# Global compliance reporting engine instance
compliance_reporting_engine = ComplianceReportingEngine()