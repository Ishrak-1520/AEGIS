"""
System Logger Module
Centralized logging for CyberGuard Pro
Handles file-based logging and event tracking
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SystemLogger:
    """
    Centralized logging system with file rotation
    """
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize system logger
        
        Args:
            log_dir: Directory for log files
        """
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'logs'
        )
        
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Create loggers
        self.app_logger = self._create_logger('app', 'cyberguard.log')
        self.threat_logger = self._create_logger('threat', 'threats.log')
        self.audit_logger = self._create_logger('audit', 'audit.log')
    
    def _create_logger(self, name: str, filename: str) -> logging.Logger:
        """
        Create logger with rotating file handler
        
        Args:
            name: Logger name
            filename: Log filename
            
        Returns:
            Configured logger
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # Avoid duplicate handlers
        if logger.handlers:
            return logger
        
        # File handler with rotation (10MB max, 5 backups)
        log_path = os.path.join(self.log_dir, filename)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=10*1024*1024,
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_info(self, message: str, logger_name: str = 'app'):
        """Log info message"""
        logger = getattr(self, f'{logger_name}_logger', self.app_logger)
        logger.info(message)
    
    def log_warning(self, message: str, logger_name: str = 'app'):
        """Log warning message"""
        logger = getattr(self, f'{logger_name}_logger', self.app_logger)
        logger.warning(message)
    
    def log_error(self, message: str, logger_name: str = 'app', exc_info: bool = False):
        """Log error message"""
        logger = getattr(self, f'{logger_name}_logger', self.app_logger)
        logger.error(message, exc_info=exc_info)
    
    def log_critical(self, message: str, logger_name: str = 'app'):
        """Log critical message"""
        logger = getattr(self, f'{logger_name}_logger', self.app_logger)
        logger.critical(message)
    
    def log_threat(self, threat_type: str, threat_level: str, details: str):
        """Log security threat"""
        message = f"[{threat_level}] {threat_type}: {details}"
        self.threat_logger.warning(message)
    
    def log_audit(self, action: str, user: str, details: str):
        """Log audit event"""
        message = f"User: {user} | Action: {action} | Details: {details}"
        self.audit_logger.info(message)


# Global logger instance
system_logger = SystemLogger()
