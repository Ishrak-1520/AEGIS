"""
NLP Threat Detection Module
Analyzes text content for cyber threats, phishing, and social engineering
Uses keyword-based pattern matching (lightweight, no ML dependencies)

Implements SRS Requirements:
- FR-NLP-01: Analyze text content using NLP algorithms
- FR-NLP-02: Detect phishing patterns in emails and messages
- FR-NLP-03: Identify social engineering attempts
- FR-NLP-04: Classify threat levels (safe, low, medium, high, critical)
- FR-NLP-05: Provide confidence scores for threat assessments
"""

import os
import sys
import re
from typing import Dict, List, Optional
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager


class NLPThreatDetector:
    """
    NLP-based threat detector using keyword and pattern matching
    Lightweight implementation without ML dependencies
    """
    
    def __init__(self):
        """Initialize threat detector with keyword databases (English + Bangla)"""
        
        # Phishing keywords (FR-NLP-02) - English
        self.phishing_keywords = [
            'verify account', 'confirm identity', 'update payment',
            'suspended account', 'unusual activity', 'click here immediately',
            'verify your account', 'confirm your identity', 'account locked',
            'urgent action required', 'verify information', 'update billing',
            'payment declined', 'account suspended', 'unusual sign-in',
            'reset password', 'security alert', 'confirm payment method',
            'click link below', 'expire', 'expiration', 'limited time',
            'act now', 'immediate action', 'within 24 hours',
            'reactivate', 'validate', 'authentication required'
        ]
        
        # Phishing keywords - Bangla (বাংলা)
        self.phishing_keywords_bangla = [
            'অ্যাকাউন্ট যাচাই', 'পরিচয় নিশ্চিত', 'পেমেন্ট আপডেট',
            'অ্যাকাউন্ট স্থগিত', 'অস্বাভাবিক কার্যকলাপ', 'এখনই ক্লিক করুন',
            'আপনার অ্যাকাউন্ট যাচাই করুন', 'আপনার পরিচয় নিশ্চিত করুন',
            'অ্যাকাউন্ট লক', 'জরুরি পদক্ষেপ প্রয়োজন', 'তথ্য যাচাই',
            'পেমেন্ট প্রত্যাখ্যান', 'অ্যাকাউন্ট বন্ধ', 'পাসওয়ার্ড রিসেট',
            'নিরাপত্তা সতর্কতা', 'লিংকে ক্লিক করুন', 'মেয়াদ শেষ',
            'সীমিত সময়', 'এখনই কাজ করুন', 'অবিলম্বে পদক্ষেপ',
            '২৪ ঘণ্টার মধ্যে', 'পুনরায় সক্রিয়', 'প্রমাণীকরণ প্রয়োজন'
        ]
        
        # Social engineering keywords (FR-NLP-03) - English
        self.social_engineering_keywords = [
            'congratulations', 'you have won', 'claim your prize',
            'free money', 'earn extra income', 'work from home',
            'inheritance', 'lottery winner', 'tax refund',
            'government grant', 'debt relief', 'credit repair',
            'risk-free', 'guaranteed', 'limited offer',
            'act immediately', 'urgent response needed', 'don\'t delay',
            'confidential', 'secret shopper', 'mystery shopper',
            'wire transfer', 'send money', 'western union',
            'gift card', 'bitcoin', 'cryptocurrency investment'
        ]
        
        # Social engineering keywords - Bangla (বাংলা)
        self.social_engineering_keywords_bangla = [
            'অভিনন্দন', 'আপনি জিতেছেন', 'আপনার পুরস্কার দাবি করুন',
            'বিনামূল্যে টাকা', 'অতিরিক্ত আয়', 'ঘরে বসে কাজ',
            'উত্তরাধিকার', 'লটারি বিজয়ী', 'কর ফেরত',
            'সরকারি অনুদান', 'ঋণ মুক্তি', 'ক্রেডিট মেরামত',
            'ঝুঁকিমুক্ত', 'গ্যারান্টিড', 'সীমিত অফার',
            'অবিলম্বে কাজ করুন', 'জরুরি প্রতিক্রিয়া প্রয়োজন', 'বিলম্ব করবেন না',
            'গোপনীয়', 'গোপন ক্রেতা', 'টাকা পাঠান', 'ওয়েস্টার্ন ইউনিয়ন',
            'গিফট কার্ড', 'বিটকয়েন', 'ক্রিপ্টোকারেন্সি বিনিয়োগ',
            'দ্রুত টাকা', 'সহজ আয়', 'লাভের সুযোগ'
        ]
        
        # Scam keywords - English
        self.scam_keywords = [
            'nigerian prince', 'foreign lottery', 'advance fee',
            'money laundering', 'offshore account', 'tax haven',
            'pyramid scheme', 'mlm', 'multi-level marketing',
            'get rich quick', 'make money fast', 'passive income',
            'investment opportunity', 'ground floor opportunity',
            'exclusive deal', 'insider information', 'stock tip', 'ilham'
        ]
        
        # Scam keywords - Bangla (বাংলা)
        self.scam_keywords_bangla = [
            'বিদেশী লটারি', 'অগ্রিম ফি', 'অর্থ পাচার',
            'পিরামিড স্কিম', 'দ্রুত ধনী হন', 'দ্রুত টাকা আয়',
            'বিনিয়োগের সুযোগ', 'এক্সক্লুসিভ ডিল', 'স্টক টিপস',
            'গোপন তথ্য', 'নিষ্ক্রিয় আয়', 'মাল্টি-লেভেল মার্কেটিং'
        ]
        
        # Malicious URL patterns
        self.suspicious_url_patterns = [
            r'bit\.ly', r'tinyurl', r'goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'https?://[a-z0-9-]+\.(tk|ml|ga|cf|gq)',  # Free domains
            r'login.*\.com', r'secure.*\.com', r'verify.*\.com',
            r'account.*\.com', r'update.*\.com'
        ]
        
        # Critical keywords (high threat) - English
        self.critical_keywords = [
            'malware', 'ransomware', 'virus', 'trojan',
            'keylogger', 'spyware', 'backdoor', 'exploit',
            'zero-day', 'vulnerability', 'crack', 'hack'
        ]
        
        # Critical keywords - Bangla (বাংলা)
        self.critical_keywords_bangla = [
            'ম্যালওয়্যার', 'র‍্যানসমওয়্যার', 'ভাইরাস', 'ট্রোজান',
            'কীলগার', 'স্পাইওয়্যার', 'হ্যাক', 'দুর্বলতা',
            'ক্র্যাক', 'শোষণ'
        ]
        
        # Urgency/threat phrases - Bangla (বাংলা)
        self.urgency_keywords_bangla = [
            'এখনই', 'জরুরি', 'অবিলম্বে', 'আজই শেষ',
            'সীমিত সময়', 'তাড়াতাড়ি', 'অপেক্ষা করবেন না',
            '২৪ ঘণ্টার মধ্যে', 'শেষ সুযোগ', 'শীঘ্রই শেষ'
        ]
        
        # Credential request - Bangla (বাংলা)
        self.credential_keywords_bangla = [
            'পাসওয়ার্ড লিখুন', 'পাসওয়ার্ড প্রদান করুন',
            'ইউজারনেম এবং পাসওয়ার্ড', 'লগইন তথ্য',
            'অ্যাকাউন্ট তথ্য', 'ক্রেডিট কার্ড', 'কার্ড নম্বর',
            'পিন নম্বর', 'পাসওয়ার্ড যাচাই', 'সামাজিক নিরাপত্তা'
        ]
        
        # Financial request - Bangla (বাংলা)
        self.financial_keywords_bangla = [
            'টাকা পাঠান', 'তার স্থানান্তর', 'ব্যাংক অ্যাকাউন্ট',
            'রাউটিং নম্বর', 'তহবিল স্থানান্তর', 'পেমেন্ট প্রয়োজন',
            'পেমেন্ট করুন', 'প্রক্রিয়াকরণ ফি', 'লেনদেন ফি',
            'এখনই পেমেন্ট', 'পেমেন্ট পদ্ধতি'
        ]
        
        # PII Regex Patterns (FR-NLP-03)
        self.pii_patterns = {
            'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone': r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b',
            'IPv4': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
    def analyze_text(self, text: str) -> Dict:
        """
        Analyze text for threats (FR-NLP-01)
        
        Args:
            text: Text content to analyze
            
        Returns:
            Analysis result dictionary with threat classification
        """
        if not text or not text.strip():
            return {
                'threat_class': 'SAFE',
                'confidence': 100.0,
                'keywords_found': [],
                'patterns_detected': [],
                'threat_level': 'SAFE',
                'description': 'No content to analyze'
            }
        
        text_lower = text.lower()
        
        # Detect patterns and keywords (English + Bangla)
        phishing_matches = self._find_keywords(text_lower, self.phishing_keywords)
        phishing_matches.extend(self._find_keywords(text, self.phishing_keywords_bangla))  # Bangla (case-sensitive)
        
        social_eng_matches = self._find_keywords(text_lower, self.social_engineering_keywords)
        social_eng_matches.extend(self._find_keywords(text, self.social_engineering_keywords_bangla))  # Bangla
        
        scam_matches = self._find_keywords(text_lower, self.scam_keywords)
        scam_matches.extend(self._find_keywords(text, self.scam_keywords_bangla))  # Bangla
        
        critical_matches = self._find_keywords(text_lower, self.critical_keywords)
        critical_matches.extend(self._find_keywords(text, self.critical_keywords_bangla))  # Bangla
        
        url_matches = self._find_suspicious_urls(text)
        
        # Calculate threat scores
        threat_score = 0
        keywords_found = []
        patterns_detected = []
        
        # Critical threats (highest priority)
        if critical_matches:
            threat_score += len(critical_matches) * 30
            keywords_found.extend(critical_matches)
            patterns_detected.append('Malware/Exploit Keywords')
        
        # Phishing patterns (FR-NLP-02)
        if phishing_matches:
            threat_score += len(phishing_matches) * 15
            keywords_found.extend(phishing_matches)
            patterns_detected.append('Phishing Indicators')
        
        # Social engineering (FR-NLP-03)
        if social_eng_matches:
            threat_score += len(social_eng_matches) * 12
            keywords_found.extend(social_eng_matches)
            patterns_detected.append('Social Engineering')
        
        # Scam patterns
        if scam_matches:
            threat_score += len(scam_matches) * 18
            keywords_found.extend(scam_matches)
            patterns_detected.append('Scam Indicators')
        
        # Suspicious URLs
        if url_matches:
            threat_score += len(url_matches) * 20
            keywords_found.extend([f"Suspicious URL: {url[:50]}" for url in url_matches])
            patterns_detected.append('Suspicious URLs')
        
        # Additional pattern checks
        if self._check_urgency_language(text_lower):
            threat_score += 10
            patterns_detected.append('Urgency Language')
        
        if self._check_credential_request(text_lower):
            threat_score += 25
            patterns_detected.append('Credential Request')
        
        if self._check_financial_request(text_lower):
            threat_score += 20
            patterns_detected.append('Financial Request')
            
        # PII Detection
        pii_matches = self._find_pii(text)
        if pii_matches:
            threat_score += len(pii_matches) * 25
            for pii_type, count in pii_matches.items():
                patterns_detected.append(f"PII Detected: {pii_type} ({count})")
                keywords_found.append(f"PII: {pii_type}")
        
        # Classify threat level (FR-NLP-04)
        threat_class, threat_level, confidence = self._classify_threat(threat_score)
        
        # Build result
        result = {
            'threat_class': threat_class,
            'threat_level': threat_level,
            'confidence': confidence,  # FR-NLP-05: Confidence score
            'keywords_found': list(set(keywords_found)),
            'patterns_detected': patterns_detected,
            'threat_score': threat_score,
            'description': self._generate_description(threat_class, patterns_detected),
            'timestamp': datetime.now().isoformat()
        }
        
        # Log analysis to database
        try:
            db_manager.log_event(
                'NLP_ANALYSIS',
                'INFO' if threat_level == 'SAFE' else 'WARNING',
                f"Text analyzed: {threat_class} (confidence: {confidence:.1f}%)"
            )
        except Exception as e:
            print(f"Error logging NLP analysis: {e}")
        
        return result
    
    def _find_keywords(self, text: str, keyword_list: List[str]) -> List[str]:
        """Find matching keywords in text"""
        found = []
        for keyword in keyword_list:
            if keyword in text:
                found.append(keyword)
        return found
    
    def _find_suspicious_urls(self, text: str) -> List[str]:
        """Find suspicious URLs in text"""
        urls = []
        for pattern in self.suspicious_url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(matches)
        
        # Also find http/https URLs
        url_pattern = r'https?://[^\s]+'
        all_urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Check for suspicious domains
        for url in all_urls:
            if any(susp in url.lower() for susp in ['login', 'verify', 'account', 'secure', 'update']):
                urls.append(url)
        
        return urls
    
    def _check_urgency_language(self, text: str) -> bool:
        """Check for urgency-creating language (English + Bangla)"""
        urgency_phrases = [
            'act now', 'urgent', 'immediately', 'expires today',
            'limited time', 'hurry', 'don\'t wait', 'expires soon',
            'within 24 hours', 'last chance', 'expiring'
        ]
        # Check English (case-insensitive)
        if any(phrase in text for phrase in urgency_phrases):
            return True
        
        # Check Bangla (case-sensitive - original text)
        return any(phrase in text for phrase in self.urgency_keywords_bangla)
    
    def _check_credential_request(self, text: str) -> bool:
        """Check for credential/password requests (English + Bangla)"""
        credential_phrases = [
            'enter password', 'provide password', 'username and password',
            'login credentials', 'account credentials', 'social security',
            'credit card', 'card number', 'cvv', 'pin number',
            'verify password', 'confirm password'
        ]
        # Check English (case-insensitive)
        if any(phrase in text for phrase in credential_phrases):
            return True
        
        # Check Bangla (case-sensitive - original text, not lowercase)
        original_text = text  # Use original for Bangla Unicode
        return any(phrase in original_text for phrase in self.credential_keywords_bangla)
    
    def _check_financial_request(self, text: str) -> bool:
        """Check for financial/money requests (English + Bangla)"""
        financial_phrases = [
            'send money', 'wire transfer', 'bank account', 'routing number',
            'transfer funds', 'payment required', 'make payment',
            'send payment', 'processing fee', 'transaction fee',
            'pay now', 'payment method'
        ]
        # Check English (case-insensitive)
        if any(phrase in text for phrase in financial_phrases):
            return True
        
        # Check Bangla (case-sensitive - original text)
        original_text = text  # Use original for Bangla Unicode
        return any(phrase in original_text for phrase in self.financial_keywords_bangla)
    
    def _find_pii(self, text: str) -> Dict[str, int]:
        """Find PII in text using regex"""
        matches = {}
        for pii_type, pattern in self.pii_patterns.items():
            found = re.findall(pattern, text)
            if found:
                # Filter out likely false positives for Credit Cards (e.g. simple numbers)
                if pii_type == 'Credit Card':
                    valid_cc = [cc for cc in found if sum(c.isdigit() for c in cc) >= 13]
                    if valid_cc:
                        matches[pii_type] = len(valid_cc)
                else:
                    matches[pii_type] = len(found)
        return matches
    
    def _classify_threat(self, threat_score: int) -> tuple:
        """
        Classify threat level based on score (FR-NLP-04)
        
        Returns:
            (threat_class, threat_level, confidence)
        """
        if threat_score >= 80:
            return ('CRITICAL_THREAT', 'CRITICAL', min(95.0, 70.0 + threat_score * 0.25))
        elif threat_score >= 50:
            return ('HIGH_THREAT', 'HIGH', min(90.0, 60.0 + threat_score * 0.4))
        elif threat_score >= 30:
            return ('MEDIUM_THREAT', 'MEDIUM', min(85.0, 50.0 + threat_score * 0.8))
        elif threat_score >= 10:
            return ('LOW_THREAT', 'LOW', min(75.0, 40.0 + threat_score * 2.0))
        else:
            return ('SAFE', 'SAFE', 100.0 - threat_score)
    
    def _generate_description(self, threat_class: str, patterns: List[str]) -> str:
        """Generate human-readable threat description"""
        if threat_class == 'SAFE':
            return "No threats detected. Content appears safe."
        elif threat_class == 'LOW_THREAT':
            return f"Low-level threat indicators detected: {', '.join(patterns[:2])}"
        elif threat_class == 'MEDIUM_THREAT':
            return f"Medium threat detected with patterns: {', '.join(patterns[:3])}"
        elif threat_class == 'HIGH_THREAT':
            return f"High threat detected! Multiple suspicious patterns: {', '.join(patterns)}"
        else:  # CRITICAL_THREAT
            return f"CRITICAL THREAT! Dangerous content detected: {', '.join(patterns)}"
    
    def get_threat_statistics(self) -> Dict:
        """Get statistics about analyzed threats"""
        try:
            events = db_manager.get_system_events(100)
            nlp_events = [e for e in events if e.get('event_type') == 'NLP_ANALYSIS']
            
            return {
                'total_analyzed': len(nlp_events),
                'threats_detected': len([e for e in nlp_events if 'THREAT' in e.get('message', '')]),
                'safe_content': len([e for e in nlp_events if 'SAFE' in e.get('message', '')])
            }
        except Exception as e:
            return {'error': str(e)}


# Singleton instance
_nlp_detector_instance = None


def get_nlp_detector() -> NLPThreatDetector:
    """
    Get singleton NLP detector instance
    
    Returns:
        NLPThreatDetector instance
    """
    global _nlp_detector_instance
    if _nlp_detector_instance is None:
        _nlp_detector_instance = NLPThreatDetector()
    return _nlp_detector_instance
