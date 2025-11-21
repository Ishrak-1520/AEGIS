"""
Explainable AI Module
Provides interpretability for NLP threat detection decisions
Uses attention visualization and keyword highlighting
"""

import os
import sys
from typing import Dict, List, Tuple, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ExplainableAI:
    """
    Provides explanations for AI threat detection decisions
    Highlights important tokens and patterns
    """
    
    def __init__(self):
        """Initialize explainable AI module"""
        self.importance_threshold = 0.5
    
    def explain_threat_detection(self, text: str, analysis_result: Dict) -> Dict:
        """
        Generate explanation for threat detection
        
        Args:
            text: Original text analyzed
            analysis_result: Result from NLP detector
            
        Returns:
            Explanation dictionary with highlighted tokens
        """
        keywords_found = analysis_result.get('keywords_found', [])
        threat_class = analysis_result.get('threat_class', 'UNKNOWN')
        confidence = analysis_result.get('confidence', 0.0)
        
        # Highlight suspicious words in text
        highlighted_text = self._highlight_keywords(text, keywords_found)
        
        # Generate importance scores for words
        word_importance = self._calculate_word_importance(text, keywords_found)
        
        # Get top contributing words
        top_words = sorted(
            word_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Generate human-readable explanation
        explanation_text = self._generate_explanation(
            threat_class,
            confidence,
            keywords_found,
            top_words
        )
        
        return {
            'highlighted_text': highlighted_text,
            'word_importance': word_importance,
            'top_contributing_words': dict(top_words),
            'explanation': explanation_text,
            'confidence': confidence,
            'threat_class': threat_class
        }
    
    def _highlight_keywords(self, text: str, keywords: List[str]) -> str:
        """
        Highlight suspicious keywords in text
        
        Args:
            text: Original text
            keywords: List of suspicious keywords
            
        Returns:
            Text with HTML/markdown highlighting
        """
        highlighted = text
        
        for keyword in keywords:
            # Case-insensitive replacement with highlighting
            import re
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            highlighted = pattern.sub(
                lambda m: f"**[{m.group()}]**",
                highlighted
            )
        
        return highlighted
    
    def _calculate_word_importance(self, text: str, 
                                   keywords: List[str]) -> Dict[str, float]:
        """
        Calculate importance score for each word
        
        Args:
            text: Original text
            keywords: Suspicious keywords
            
        Returns:
            Dictionary mapping words to importance scores
        """
        words = text.lower().split()
        word_importance = {}
        
        for word in set(words):
            # Clean word
            cleaned_word = ''.join(c for c in word if c.isalnum())
            if not cleaned_word:
                continue
            
            # Base importance
            importance = 0.0
            
            # Check if word matches a keyword
            for keyword in keywords:
                if cleaned_word in keyword.lower() or keyword.lower() in cleaned_word:
                    importance = max(importance, 0.9)
                    break
            
            # Additional scoring based on suspicious patterns
            if len(cleaned_word) > 0:
                # Urgent/action words
                if cleaned_word in ['urgent', 'immediate', 'now', 'verify', 'confirm']:
                    importance = max(importance, 0.7)
                
                # Financial words
                elif cleaned_word in ['account', 'bank', 'payment', 'money', 'transfer']:
                    importance = max(importance, 0.6)
                
                # Authority words
                elif cleaned_word in ['government', 'irs', 'police', 'legal']:
                    importance = max(importance, 0.5)
            
            if importance > 0:
                word_importance[word] = importance
        
        return word_importance
    
    def _generate_explanation(self, threat_class: str, confidence: float,
                             keywords: List[str], top_words: List[Tuple[str, float]]) -> str:
        """
        Generate human-readable explanation
        
        Args:
            threat_class: Detected threat class
            confidence: Confidence score
            keywords: Suspicious keywords found
            top_words: Top contributing words
            
        Returns:
            Explanation text
        """
        if threat_class == 'SAFE':
            return "No suspicious content detected. The text appears to be legitimate."
        
        explanation = f"⚠️ Threat Detected: {threat_class}\n"
        explanation += f"Confidence Level: {confidence:.1%}\n\n"
        
        explanation += "Why this was flagged:\n"
        
        if keywords:
            explanation += f"• Found {len(keywords)} suspicious keyword(s):\n"
            for keyword in keywords[:5]:  # Show top 5
                explanation += f"  - '{keyword}'\n"
        
        if top_words:
            explanation += f"\n• Most suspicious words in the text:\n"
            for word, score in top_words[:5]:
                explanation += f"  - '{word}' (importance: {score:.2f})\n"
        
        # Add specific threat type explanation
        if threat_class == 'PHISHING':
            explanation += "\n📧 This appears to be a phishing attempt trying to steal your credentials or personal information."
        elif threat_class == 'SCAM':
            explanation += "\n💰 This appears to be a scam trying to defraud you of money or sensitive information."
        elif threat_class == 'SOCIAL_ENGINEERING':
            explanation += "\n🎭 This uses social engineering tactics to manipulate you into taking unsafe actions."
        elif threat_class == 'MALWARE_LINK':
            explanation += "\n🔗 This may contain links to malware or malicious websites."
        
        explanation += "\n\n⚡ Recommended Action: Do not respond to or click any links in this message."
        
        return explanation
    
    def visualize_attention(self, text: str, word_importance: Dict[str, float]) -> str:
        """
        Create ASCII visualization of word importance
        
        Args:
            text: Original text
            word_importance: Word importance scores
            
        Returns:
            ASCII visualization
        """
        words = text.split()
        visualization = []
        
        for word in words:
            cleaned = ''.join(c for c in word.lower() if c.isalnum())
            importance = word_importance.get(word.lower(), 0.0)
            
            # Create visual indicator
            if importance > 0.7:
                indicator = "🔴"  # High importance
            elif importance > 0.5:
                indicator = "🟡"  # Medium importance
            elif importance > 0.3:
                indicator = "🟢"  # Low importance
            else:
                indicator = "⚪"  # No importance
            
            visualization.append(f"{indicator}{word}")
        
        return " ".join(visualization)
    
    def get_decision_factors(self, analysis_result: Dict) -> List[Dict]:
        """
        Extract key decision factors from analysis
        
        Args:
            analysis_result: Analysis result dictionary
            
        Returns:
            List of decision factors
        """
        factors = []
        
        # Keyword factors
        keywords = analysis_result.get('keywords_found', [])
        if keywords:
            factors.append({
                'factor': 'Suspicious Keywords',
                'impact': 'HIGH',
                'description': f"Found {len(keywords)} suspicious keywords",
                'details': keywords[:5]
            })
        
        # Confidence factor
        confidence = analysis_result.get('confidence', 0.0)
        if confidence > 0.7:
            factors.append({
                'factor': 'High Confidence Score',
                'impact': 'HIGH',
                'description': f"Model confidence: {confidence:.1%}",
                'details': []
            })
        
        # Model probabilities (if available)
        if 'model_probabilities' in analysis_result:
            probs = analysis_result['model_probabilities']
            top_prob = max(probs.items(), key=lambda x: x[1])
            factors.append({
                'factor': 'Model Prediction',
                'impact': 'MEDIUM',
                'description': f"Predicted as {top_prob[0]}",
                'details': dict(sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3])
            })
        
        return factors


# Global instance
explainable_ai = ExplainableAI()
