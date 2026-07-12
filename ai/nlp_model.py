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

import json
import os
import sys
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from core.sift_engine import SiftEngine


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
        
        # Web browsing threat keywords (clickjacking, ad popups, fake prompts)
        self.web_threat_keywords = [
            # Fake notification/permission prompts
            'click allow to continue', 'click allow to verify',
            'press allow to watch', 'click allow to access',
            'enable notifications', 'allow notifications',
            'confirm you are not a robot', 'prove you are human',
            'click to continue watching',
            
            # Clickjacking / deceptive overlays
            'click here to claim', 'click here to download',
            'download now', 'install now', 'update now',
            'your download is ready', 'start download',
            'click anywhere to close',
            
            # Fake virus / tech support scams on websites
            'your computer is infected', 'virus detected on your',
            'your device has been compromised',
            'call this number', 'call microsoft support',
            'your pc is at risk', 'system warning detected',
            'windows defender alert',
            
            # Fake captcha / age gates used for clickjacking
            'confirm that you are over 18',
            'click to verify your age', 'are you over 18',
            'human verification required',
            
            # Deceptive ad language
            'congratulations you\'ve been selected',
            'you are the lucky visitor',
            'spin the wheel', 'claim your reward',
            'you have 1 new message', 'unread messages',
            'someone is trying to contact you',
            
            # Browser hijacking
            'add extension', 'install extension',
            'your browser is out of date', 'update your browser',
            'flash player is required', 'plugin required',
            
            # Streaming site specific
            'disable adblock to watch', 'turn off ad blocker',
            'watch free movies', 'free streaming',
            'hd quality movies free',
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
                'description': 'No content to analyze',
                'matches': []
            }
            
        # Limit text size to prevent DoS (100KB)
        if len(text) > 100000:
            text = text[:100000]
        
        text_lower = text.lower()
        all_matches = []
        
        # Detect patterns and keywords (English + Bangla)
        # We now collect detailed match info: (keyword, start_index, end_index, type)
        
        phishing_matches = self._find_keywords_with_indices(text, self.phishing_keywords, 'Phishing')
        phishing_matches.extend(self._find_keywords_with_indices(text, self.phishing_keywords_bangla, 'Phishing'))
        all_matches.extend(phishing_matches)
        
        social_eng_matches = self._find_keywords_with_indices(text, self.social_engineering_keywords, 'Social Engineering')
        social_eng_matches.extend(self._find_keywords_with_indices(text, self.social_engineering_keywords_bangla, 'Social Engineering'))
        all_matches.extend(social_eng_matches)
        
        scam_matches = self._find_keywords_with_indices(text, self.scam_keywords, 'Scam')
        scam_matches.extend(self._find_keywords_with_indices(text, self.scam_keywords_bangla, 'Scam'))
        all_matches.extend(scam_matches)
        
        critical_matches = self._find_keywords_with_indices(text, self.critical_keywords, 'Critical')
        critical_matches.extend(self._find_keywords_with_indices(text, self.critical_keywords_bangla, 'Critical'))
        all_matches.extend(critical_matches)
        
        web_threat_matches = self._find_keywords_with_indices(text, self.web_threat_keywords, 'Web Threat')
        all_matches.extend(web_threat_matches)
        
        url_matches = self._find_suspicious_urls_with_indices(text)
        all_matches.extend(url_matches)
        
        # Calculate threat scores
        threat_score = 0
        keywords_found = []
        patterns_detected = []
        
        # Helper to extract just the keyword strings for legacy support/logging
        phishing_keywords = [m['text'] for m in phishing_matches]
        social_eng_keywords = [m['text'] for m in social_eng_matches]
        scam_keywords = [m['text'] for m in scam_matches]
        critical_keywords = [m['text'] for m in critical_matches]
        url_keywords = [m['text'] for m in url_matches]
        
        # Critical threats (highest priority)
        if critical_matches:
            threat_score += len(critical_matches) * 30
            keywords_found.extend(critical_keywords)
            patterns_detected.append('Malware/Exploit Keywords')
        
        # Phishing patterns (FR-NLP-02)
        if phishing_matches:
            threat_score += len(phishing_matches) * 15
            keywords_found.extend(phishing_keywords)
            patterns_detected.append('Phishing Indicators')
        
        # Social engineering (FR-NLP-03)
        if social_eng_matches:
            threat_score += len(social_eng_matches) * 12
            keywords_found.extend(social_eng_keywords)
            patterns_detected.append('Social Engineering')
        
        # Scam patterns
        if scam_matches:
            threat_score += len(scam_matches) * 18
            keywords_found.extend(scam_keywords)
            patterns_detected.append('Scam Indicators')
        
        # Suspicious URLs
        if url_matches:
            threat_score += len(url_matches) * 20
            keywords_found.extend([f"Suspicious URL: {url[:50]}" for url in url_keywords])
            patterns_detected.append('Suspicious URLs')
        
        # Web browsing threats (clickjacking, fake prompts, ad popups)
        web_threat_kws = [m['text'] for m in web_threat_matches]
        if web_threat_matches:
            threat_score += len(web_threat_matches) * 20
            keywords_found.extend(web_threat_kws)
            patterns_detected.append('Web Browsing Threat')
        
        # Additional pattern checks (Urgency, Credential, Financial)
        # Note: These are broader context checks, might not map to specific highlights easily without regex
        # For now, we'll keep them as score modifiers but try to highlight if possible
        
        urgency_matches = self._find_keywords_with_indices(text, [
            'act now', 'urgent', 'immediately', 'expires today',
            'limited time', 'hurry', 'don\'t wait', 'expires soon',
            'within 24 hours', 'last chance', 'expiring'
        ] + self.urgency_keywords_bangla, 'Urgency')
        
        if urgency_matches:
            threat_score += 10
            patterns_detected.append('Urgency Language')
            all_matches.extend(urgency_matches)
        
        credential_matches = self._find_keywords_with_indices(text, [
            'enter password', 'provide password', 'username and password',
            'login credentials', 'account credentials', 'social security',
            'credit card', 'card number', 'cvv', 'pin number',
            'verify password', 'confirm password'
        ] + self.credential_keywords_bangla, 'Credential Request')
        
        if credential_matches:
            threat_score += 25
            patterns_detected.append('Credential Request')
            all_matches.extend(credential_matches)
            
        financial_matches = self._find_keywords_with_indices(text, [
            'send money', 'wire transfer', 'bank account', 'routing number',
            'transfer funds', 'payment required', 'make payment',
            'send payment', 'processing fee', 'transaction fee',
            'pay now', 'payment method'
        ] + self.financial_keywords_bangla, 'Financial Request')
        
        if financial_matches:
            threat_score += 20
            patterns_detected.append('Financial Request')
            all_matches.extend(financial_matches)
            
        # PII Detection
        pii_matches_list = self._find_pii_with_indices(text)
        if pii_matches_list:
            threat_score += len(pii_matches_list) * 25
            pii_types = {}
            for m in pii_matches_list:
                pii_type = m['type']
                pii_types[pii_type] = pii_types.get(pii_type, 0) + 1
                all_matches.append(m)
                
            for pii_type, count in pii_types.items():
                patterns_detected.append(f"PII Detected: {pii_type} ({count})")
                keywords_found.append(f"PII: {pii_type}")
        
        # Classify threat level (FR-NLP-04)
        threat_class, threat_level, confidence = self._classify_threat(threat_score)
        
        description = self._generate_description(threat_class, patterns_detected)

        # --- AI CONTEXT VERIFICATION (MEDIUM threats only) ---
        # HIGH and CRITICAL are high-confidence keyword matches and alert IMMEDIATELY for speed.
        # Only MEDIUM-level matches are ambiguous enough to require LLM context validation.
        if threat_level == "MEDIUM":
            sift_api_key = os.getenv('SIFT_API_KEY')
            if sift_api_key:
                try:
                    sift_engine = SiftEngine(api_key=sift_api_key, model="LongCat-2.0-Preview")
                    # Limit text sent to LLM to prevent enormous token usage on huge screens
                    llm_text = text[:4000] if len(text) > 4000 else text
                    llm_result = sift_engine.analyze_screen_text(llm_text)
                    
                    if llm_result.get("threat_level") == "SAFE":
                        # The LLM determined this was benign context, override the local result.
                        threat_class = "SAFE"
                        threat_level = "SAFE"
                        confidence = 100.0 - llm_result.get("confidence", 80) # Invert confidence for SAFE
                        patterns_detected = ["Cleared by AI Context Analysis"] + patterns_detected
                        description = llm_result.get("description", "No threats detected. Content appears safe.")
                    else:
                        # LLM confirms or adjusts the threat level
                        new_level = llm_result.get("threat_level", threat_level)
                        if new_level != "UNKNOWN":
                            threat_level = new_level
                            
                        # Update threat_class based on new generic level
                        if threat_level == "CRITICAL":
                            threat_class = "CRITICAL_THREAT"
                        elif threat_level == "HIGH":
                            threat_class = "HIGH_THREAT"
                        elif threat_level == "MEDIUM":
                            threat_class = "MEDIUM_THREAT"
                        elif threat_level == "LOW":
                            threat_class = "LOW_THREAT"
                            
                        confidence = float(llm_result.get("confidence", confidence))
                        
                        if llm_result.get("patterns_detected"):
                            patterns_detected = llm_result.get("patterns_detected", []) + patterns_detected
                            
                        if llm_result.get("description"):
                            description = llm_result.get("description")
                except Exception as e:
                    print(f"SiftEngine verification failed: {e}")

        # Build result
        result = {
            'threat_class': threat_class,
            'threat_level': threat_level,
            'confidence': confidence,  # FR-NLP-05: Confidence score
            'keywords_found': list(set(keywords_found)),
            'patterns_detected': patterns_detected,
            'threat_score': threat_score,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'matches': all_matches # New field for frontend highlighting
        }
        
        # Log analysis to database
        try:
            db_manager.log_event(
                'NLP_ANALYSIS',
                'INFO' if threat_level == 'SAFE' else 'WARNING',
                f"Text analyzed: {threat_class} (confidence: {confidence:.1f}%)",
                json.dumps(result)  # Store full result in details
            )
        except Exception as e:
            print(f"Error logging NLP analysis: {e}")
        
        return result
    
    def _find_keywords_with_indices(self, text: str, keyword_list: List[str], match_type: str) -> List[Dict]:
        """Find matching keywords with start/end indices"""
        matches = []
        text_lower = text.lower()
        
        for keyword in keyword_list:
            keyword_lower = keyword.lower()
            # Use regex escape to handle special chars in keywords
            # Word boundary check is safer for English, but might break some Bangla phrases or compound words
            # For simplicity and robustness with phrases, we'll just do substring search first
            # To get indices, we use re.finditer
            
            try:
                pattern = re.escape(keyword_lower)
                # We iterate over the lowercased text to find matches
                for m in re.finditer(pattern, text_lower):
                    matches.append({
                        'text': text[m.start():m.end()], # Get original text case
                        'start': m.start(),
                        'end': m.end(),
                        'type': match_type
                    })
            except Exception:
                continue
                
        return matches

    def _find_keywords(self, text: str, keyword_list: List[str]) -> List[str]:
        """Legacy method: Find matching keywords in text"""
        found = []
        for keyword in keyword_list:
            if keyword.lower() in text.lower():
                found.append(keyword)
        return found
    
    def _find_suspicious_urls_with_indices(self, text: str) -> List[Dict]:
        """Find suspicious URLs with indices"""
        matches = []
        
        # Check specific patterns
        for pattern in self.suspicious_url_patterns:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                matches.append({
                    'text': m.group(),
                    'start': m.start(),
                    'end': m.end(),
                    'type': 'Suspicious URL'
                })
        
        # Check generic HTTP/HTTPS URLs for suspicious keywords
        url_pattern = r'https?://[^\s]+'
        for m in re.finditer(url_pattern, text, re.IGNORECASE):
            url = m.group()
            if any(susp in url.lower() for susp in ['login', 'verify', 'account', 'secure', 'update']):
                # Avoid duplicates if already caught by specific patterns
                # Simple check: if this range isn't already covered
                is_duplicate = False
                for existing in matches:
                    if existing['start'] == m.start() and existing['end'] == m.end():
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    matches.append({
                        'text': url,
                        'start': m.start(),
                        'end': m.end(),
                        'type': 'Suspicious URL'
                    })
        
        return matches

    def _find_suspicious_urls(self, text: str) -> List[str]:
        """Legacy method"""
        urls = []
        matches = self._find_suspicious_urls_with_indices(text)
        return [m['text'] for m in matches]
    
    def _check_urgency_language(self, text: str) -> bool:
        """Check for urgency-creating language (English + Bangla)"""
        # Reusing the logic but just returning bool for score calculation
        # The actual matches are now collected in analyze_text via _find_keywords_with_indices
        urgency_phrases = [
            'act now', 'urgent', 'immediately', 'expires today',
            'limited time', 'hurry', 'don\'t wait', 'expires soon',
            'within 24 hours', 'last chance', 'expiring'
        ]
        text_lower = text.lower()
        if any(phrase in text_lower for phrase in urgency_phrases):
            return True
        return any(phrase in text for phrase in self.urgency_keywords_bangla)
    
    def _check_credential_request(self, text: str) -> bool:
        """Check for credential/password requests"""
        credential_phrases = [
            'enter password', 'provide password', 'username and password',
            'login credentials', 'account credentials', 'social security',
            'credit card', 'card number', 'cvv', 'pin number',
            'verify password', 'confirm password'
        ]
        text_lower = text.lower()
        if any(phrase in text_lower for phrase in credential_phrases):
            return True
        return any(phrase in text for phrase in self.credential_keywords_bangla)
    
    def _check_financial_request(self, text: str) -> bool:
        """Check for financial/money requests"""
        financial_phrases = [
            'send money', 'wire transfer', 'bank account', 'routing number',
            'transfer funds', 'payment required', 'make payment',
            'send payment', 'processing fee', 'transaction fee',
            'pay now', 'payment method'
        ]
        text_lower = text.lower()
        if any(phrase in text_lower for phrase in financial_phrases):
            return True
        return any(phrase in text for phrase in self.financial_keywords_bangla)
    
    def _find_pii_with_indices(self, text: str) -> List[Dict]:
        """Find PII with indices"""
        matches = []
        for pii_type, pattern in self.pii_patterns.items():
            for m in re.finditer(pattern, text):
                text_match = m.group()
                # Filter out likely false positives for Credit Cards
                if pii_type == 'Credit Card':
                    if sum(c.isdigit() for c in text_match) < 13:
                        continue
                
                matches.append({
                    'text': text_match,
                    'start': m.start(),
                    'end': m.end(),
                    'type': pii_type
                })
        return matches

    def _find_pii(self, text: str) -> Dict[str, int]:
        """Legacy method"""
        matches = {}
        found_list = self._find_pii_with_indices(text)
        for m in found_list:
            pii_type = m['type']
            matches[pii_type] = matches.get(pii_type, 0) + 1
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
