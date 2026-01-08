import sys
import time
import signal
import logging
from pathlib import Path

from .config import Config
from .log_monitor import LogMonitor
from .detector import AnomalyDetector
from .firewall import FirewallManager
import json
from datetime import datetime


class SSHGuardService:
    def __init__(self, config_path: str = '/etc/sshguard/sshguard.conf'):
        self.running = False
        self.config = Config(config_path)
        self.setup_logging()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing SSHGuard...")
        
        self.metrics = {
            'total_events_parsed': 0,
            'total_analyses_performed': 0,
            'total_attacks_detected': 0,
            'total_ips_blocked': 0,
            'detection_history': [],
            'start_time': time.time()
        }
        
        try:
            self.monitor = LogMonitor(
                log_file=self.config.get('general', 'log_file'),
                window_size=self.config.get_int('general', 'window_size', 100)
            )
            
            self.detector = AnomalyDetector(
                model_path=self.config.get('general', 'model_path'),
                threshold=self.config.get_float('general', 'detection_threshold', 0.5),
                window_seconds=self.config.get_int('general', 'window_seconds', 3600)
            )
            
            if self.config.get_bool('firewall', 'enabled', True):
                self.firewall = FirewallManager(
                    chain_name=self.config.get('firewall', 'chain_name', 'SSHGUARD'),
                    block_duration=self.config.get_int('firewall', 'block_duration', 3600)
                )
            else:
                self.firewall = None
                self.logger.warning("Firewall blocking is disabled")
            
            self.logger.info("SSHGuard initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SSHGuard: {e}")
            raise
    
    def setup_logging(self):
        log_level = self.config.get('logging', 'log_level', 'INFO')
        log_path = self.config.get('logging', 'log_path', '/var/log/sshguard.log')
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_path) if Path(log_path).parent.exists() else logging.NullHandler()
            ]
        )
    
    def handle_shutdown(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def run(self):
        self.running = True
        
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        self.logger.info("Starting SSHGuard monitoring...")
        
        last_cleanup = time.time()
        cleanup_interval = 60
        
        try:
            for line in self.monitor.start_tail():
                if not self.running:
                    break
                
                event = self.monitor.parse_line(line)
                
                if event:
                    self.metrics['total_events_parsed'] += 1
                    self.logger.info(f"Parsed SSH event: {event}")
                    
                    self.monitor.add_event(event)
                    
                    events = self.monitor.get_event_sequence(
                        event.ip, 
                        max_age_seconds=self.detector.window_seconds
                    )
                    
                    if len(events) >= 3:
                        self.metrics['total_analyses_performed'] += 1
                        analysis_start = time.time()
                        
                        self.logger.info(f"Analyzing {len(events)} events for IP {event.ip}")
                        
                        try:
                            analysis = self.detector.analyze_ip(event.ip, events)
                            analysis_time = time.time() - analysis_start
                            
                            self.logger.info(
                                f"Analysis result: ip={analysis['ip']} "
                                f"class={analysis.get('predicted_class','-')} "
                                f"score={analysis['score']:.3f} "
                                f"benign={analysis.get('class_probs',{}).get('BENIGN',0):.3f} "
                                f"fast={analysis.get('class_probs',{}).get('FAST_ATTACK',0):.3f} "
                                f"slow={analysis.get('class_probs',{}).get('SLOW_ATTACK',0):.3f} "
                                f"events={analysis['event_count']}"
                            )
                            self.logger.info(f"Analysis took {analysis_time:.3f}s")
                            
                            detection_record = {
                                'timestamp': datetime.now().isoformat(),
                                'ip': event.ip,
                                'event_count': len(events),
                                'score': analysis['score'],
                                'is_attack': analysis['is_attack'],
                                'threshold': analysis['threshold'],
                                'analysis_time_ms': analysis_time * 1000,
                                'event_types': analysis['event_types']
                            }
                            self.metrics['detection_history'].append(detection_record)
                            
                            if analysis['is_attack']:
                                self.metrics['total_attacks_detected'] += 1
                                
                                self.logger.warning(
                                    f"ATTACK DETECTED from {analysis['ip']} "
                                    f"(score: {analysis['score']:.3f}, events: {len(events)})"
                                )
                                
                                if self.firewall and not self.firewall.is_blocked(event.ip):
                                    self.metrics['total_ips_blocked'] += 1
                                    self.firewall.block_ip(
                                        event.ip,
                                        f"Anomaly score: {analysis['score']:.3f}"
                                    )
                                    
                                    self.logger.warning(
                                        f"IP BLOCKED: {event.ip} | "
                                        f"Score: {analysis['score']:.3f} | "
                                        f"Events: {len(events)} | "
                                        f"Failed: {analysis['event_types'].get('failed_password', 0)} | "
                                        f"Auth Fail: {analysis['event_types'].get('auth_failure', 0)} | "
                                        f"Invalid: {analysis['event_types'].get('invalid_user', 0)}"
                                    )
                                else:
                                    self.logger.info(f"IP {event.ip} already blocked or firewall disabled")
                            else:
                                self.logger.info(
                                    f"No attack detected for {event.ip} "
                                    f"(score: {analysis['score']:.3f}, threshold: {analysis['threshold']})"
                                )
                            
                            if self.metrics['total_analyses_performed'] % 10 == 0:
                                self._log_metrics_summary()
                        
                        except Exception as e:
                            self.logger.error(f"Error during analysis: {e}", exc_info=True)
                
                current_time = time.time()
                if self.firewall and (current_time - last_cleanup) >= cleanup_interval:
                    self.firewall.cleanup_expired()
                    last_cleanup = current_time
        
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}", exc_info=True)
        
        finally:
            self._log_final_metrics()
            self.shutdown()
    
    def shutdown(self):
        self.logger.info("Shutting down SSHGuard...")
        
        if hasattr(self, 'monitor'):
            self.monitor.stop_tail()
        
        self.logger.info("SSHGuard stopped")
    
    def _log_metrics_summary(self):
        uptime = time.time() - self.metrics['start_time']
        
        events_per_min = (self.metrics['total_events_parsed'] / uptime) * 60 if uptime > 0 else 0
        analyses_per_min = (self.metrics['total_analyses_performed'] / uptime) * 60 if uptime > 0 else 0
        
        detection_rate = (self.metrics['total_attacks_detected'] / self.metrics['total_analyses_performed'] * 100) if self.metrics['total_analyses_performed'] > 0 else 0
        
        recent_scores = [d['score'] for d in self.metrics['detection_history'][-5:]]
        avg_recent_score = sum(recent_scores) / len(recent_scores) if recent_scores else 0
        
        self.logger.info(
            f"METRICS SUMMARY | "
            f"Uptime: {uptime/60:.1f}min | "
            f"Events: {self.metrics['total_events_parsed']} ({events_per_min:.1f}/min) | "
            f"Analyses: {self.metrics['total_analyses_performed']} ({analyses_per_min:.1f}/min) | "
            f"Attacks: {self.metrics['total_attacks_detected']} ({detection_rate:.1f}%) | "
            f"Blocked: {self.metrics['total_ips_blocked']} | "
            f"Avg Score: {avg_recent_score:.3f}"
        )
    
    def _log_final_metrics(self):
        uptime = time.time() - self.metrics['start_time']
        
        if self.metrics['detection_history']:
            all_scores = [d['score'] for d in self.metrics['detection_history']]
            attack_scores = [d['score'] for d in self.metrics['detection_history'] if d['is_attack']]
            benign_scores = [d['score'] for d in self.metrics['detection_history'] if not d['is_attack']]
            
            stats = {
                'session_duration_minutes': uptime / 60,
                'total_events_parsed': self.metrics['total_events_parsed'],
                'total_analyses_performed': self.metrics['total_analyses_performed'],
                'total_attacks_detected': self.metrics['total_attacks_detected'],
                'total_ips_blocked': self.metrics['total_ips_blocked'],
                'detection_rate_percent': (self.metrics['total_attacks_detected'] / self.metrics['total_analyses_performed'] * 100) if self.metrics['total_analyses_performed'] > 0 else 0,
                'avg_score_all': sum(all_scores) / len(all_scores),
                'avg_score_attacks': sum(attack_scores) / len(attack_scores) if attack_scores else 0,
                'avg_score_benign': sum(benign_scores) / len(benign_scores) if benign_scores else 0,
                'max_score': max(all_scores),
                'min_score': min(all_scores)
            }
            
            self.logger.info(f"FINAL METRICS: {json.dumps(stats, indent=2)}")
        
        try:
            metrics_file = f"/tmp/sshguard_metrics_{int(time.time())}.json"
            with open(metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2, default=str)
            self.logger.info(f"Detailed metrics saved to: {metrics_file}")
        except Exception as e:
            self.logger.error(f"Failed to save metrics: {e}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SSHGuard - LSTM-based SSH intrusion detection')
    parser.add_argument(
        '-c', '--config',
        default='/etc/sshguard/sshguard.conf',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    try:
        service = SSHGuardService(config_path=args.config)
        service.run()
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
