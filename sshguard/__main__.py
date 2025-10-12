"""Main entry point for SSHGuard service."""

import sys
import time
import signal
import logging
from pathlib import Path

from .config import Config
from .log_monitor import LogMonitor
from .detector import AnomalyDetector
from .firewall import FirewallManager


class SSHGuardService:
    """Main SSHGuard service."""
    
    def __init__(self, config_path: str = '/etc/sshguard/sshguard.conf'):
        """Initialize SSHGuard service.
        
        Args:
            config_path: Path to configuration file
        """
        self.running = False
        self.config = Config(config_path)
        self.setup_logging()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing SSHGuard...")
        
        # Initialize components
        try:
            self.monitor = LogMonitor(
                log_file=self.config.get('general', 'log_file'),
                window_size=self.config.get_int('general', 'window_size', 100)
            )
            
            self.detector = AnomalyDetector(
                model_path=self.config.get('general', 'model_path'),
                threshold=self.config.get_float('general', 'detection_threshold', 0.8)
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
        """Setup logging configuration."""
        log_level = self.config.get('logging', 'log_level', 'INFO')
        log_path = self.config.get('logging', 'log_path', '/var/log/sshguard.log')
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_path) if Path(log_path).parent.exists() else logging.NullHandler()
            ]
        )
    
    def handle_shutdown(self, signum, frame):
        """Handle shutdown signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def run(self):
        """Run the main service loop."""
        self.running = True
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        self.logger.info("Starting SSHGuard monitoring...")
        
        # Track last cleanup time
        last_cleanup = time.time()
        cleanup_interval = 60  # Cleanup expired blocks every 60 seconds
        
        try:
            # Start monitoring log file
            for line in self.monitor.start_tail():
                if not self.running:
                    break
                
                # Parse log line
                event = self.monitor.parse_line(line)
                
                if event:
                    self.logger.info(f"Parsed SSH event: {event}")
                    
                    # Add event to IP window
                    self.monitor.add_event(event)
                    
                    # Get event sequence for this IP
                    events = self.monitor.get_event_sequence(event.ip)
                    
                    # Only analyze if we have enough events (lowered for testing)
                    if len(events) >= 3:
                        self.logger.info(f"Analyzing {len(events)} events for IP {event.ip}")
                        
                        # Run detection
                        try:
                            analysis = self.detector.analyze_ip(event.ip, events)
                            self.logger.info(f"Analysis result: {analysis}")
                            
                            if analysis['is_attack']:
                                self.logger.warning(
                                    f"Attack detected from {analysis['ip']} "
                                    f"(score: {analysis['score']:.3f})"
                                )
                                
                                # Block IP if firewall is enabled
                                if self.firewall and not self.firewall.is_blocked(event.ip):
                                    self.firewall.block_ip(
                                        event.ip,
                                        f"Anomaly score: {analysis['score']:.3f}"
                                    )
                                else:
                                    self.logger.info(f"IP {event.ip} already blocked or firewall disabled")
                            else:
                                self.logger.info(f"No attack detected for {event.ip} (score: {analysis['score']:.3f}, threshold: {analysis['threshold']})")
                        
                        except Exception as e:
                            self.logger.error(f"Error during analysis: {e}", exc_info=True)
                
                # Periodic cleanup of expired blocks
                current_time = time.time()
                if self.firewall and (current_time - last_cleanup) >= cleanup_interval:
                    self.firewall.cleanup_expired()
                    last_cleanup = current_time
        
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}", exc_info=True)
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Cleanup and shutdown."""
        self.logger.info("Shutting down SSHGuard...")
        
        # Stop log monitoring
        if hasattr(self, 'monitor'):
            self.monitor.stop_tail()
        
        # Cleanup firewall (optional - keeps blocks active)
        # Uncomment the following line to remove all blocks on shutdown:
        # if hasattr(self, 'firewall') and self.firewall:
        #     self.firewall.cleanup_chain()
        
        self.logger.info("SSHGuard stopped")


def main():
    """Main entry point."""
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

