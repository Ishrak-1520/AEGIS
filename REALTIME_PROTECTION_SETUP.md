# Real-Time Protection Feature - Setup Guide

## Overview

The **Real-Time Protection** feature is an advanced cybersecurity module that continuously monitors your screen content for potential threats including phishing, social engineering, malware indicators, and suspicious URLs.

### Key Features

- ✅ **Continuous Screen Monitoring**: Scans visible screen content at regular intervals
- ✅ **AI-Powered Threat Detection**: Uses NLP algorithms to analyze text for cyber threats
- ✅ **Instant Popup Alerts**: Immediate notifications when threats are detected
- ✅ **Threat Classification**: Categorizes threats as SAFE, LOW, MEDIUM, HIGH, or CRITICAL
- ✅ **Confidence Scoring**: Provides percentage-based confidence scores for detections
- ✅ **Recommended Actions**: Suggests appropriate responses for each threat level
- ✅ **Configurable Sensitivity**: Adjust scanning interval and threat sensitivity
- ✅ **Performance Optimized**: Minimal CPU/memory impact during operation
- ✅ **Database Logging**: All detections logged for audit and review

## System Requirements

### Required Dependencies

1. **Pillow (PIL)** - For screen capture
   ```bash
   pip install Pillow>=10.0.0
   ```

2. **pytesseract** - For OCR text extraction
   ```bash
   pip install pytesseract>=0.3.10
   ```

3. **Tesseract OCR Engine** - System-level OCR software
   
   **Windows Installation:**
   - Download installer from: https://github.com/UB-Mannheim/tesseract/wiki
   - Run the installer (e.g., `tesseract-ocr-w64-setup-5.3.3.exe`)
   - Add Tesseract to PATH or configure pytesseract path in code
   
   **Default Windows Installation Path:**
   ```
   C:\Program Files\Tesseract-OCR\tesseract.exe
   ```
   
   **Linux Installation:**
   ```bash
   sudo apt-get install tesseract-ocr
   ```
   
   **macOS Installation:**
   ```bash
   brew install tesseract
   ```

### Verify Installation

Run this Python snippet to verify:

```python
import pytesseract
from PIL import Image

# Windows: Set tesseract path if not in PATH
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Test OCR
print("Tesseract version:", pytesseract.get_tesseract_version())
```

## Installation Steps

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Tesseract OCR** (see above based on your OS)

3. **Configure Tesseract Path** (Windows only, if not in PATH)
   
   Edit `core/realtime_protection.py` and add at the top:
   ```python
   import pytesseract
   pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
   ```

4. **Launch CyberGuard Pro**
   ```bash
   python main.py
   ```

## Using Real-Time Protection

### Starting Protection

1. Log into CyberGuard Pro
2. On the **Overview** tab, locate the "🛡️ Real-Time Protection" section
3. Click **"▶ Start Real-Time Protection"** button
4. A confirmation dialog will appear
5. Protection is now active and monitoring your screen

### Configuration

Click **"⚙️ Configure Settings"** to adjust:

- **Scan Interval**: How often to scan the screen (1-10 seconds)
  - Lower = More frequent scans, higher CPU usage
  - Higher = Less frequent scans, lower CPU usage
  - Recommended: 3-5 seconds

- **Threat Sensitivity**: What threat levels trigger alerts
  - **LOW**: Only CRITICAL and HIGH threats
  - **MEDIUM**: CRITICAL, HIGH, and MEDIUM threats (recommended)
  - **HIGH**: All threat levels including LOW

### Threat Alerts

When a threat is detected, you'll see a popup alert with:

- **Threat Level**: CRITICAL, HIGH, MEDIUM, or LOW
- **Confidence Score**: Detection confidence percentage
- **Description**: What was detected
- **Detected Patterns**: Specific threat indicators (e.g., "Phishing Indicators", "Suspicious URLs")
- **Recommended Actions**: Suggested steps to take
- **Action Buttons**:
  - **✓ Dismiss**: Acknowledge and close alert
  - **ⓘ View Details**: See full threat analysis
  - **🚫 Block & Close**: For HIGH/CRITICAL threats, take immediate action

### Stopping Protection

1. Click **"⏸ Stop Real-Time Protection"** button
2. Protection stops immediately
3. Statistics (scans performed, threats detected) are preserved

## How It Works

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Real-Time Protection Pipeline               │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Screen Capture     │  ← Pillow (PIL) ImageGrab
│  (Every N seconds)  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  OCR Text           │  ← Tesseract pytesseract
│  Extraction         │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  NLP Threat         │  ← ai/nlp_model.py
│  Analysis           │     (Keyword/Pattern Matching)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Threat             │  ← If threat detected
│  Classification     │     (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Popup Alert        │  ← gui/popup_alerts.py
│  (if threat found)  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Database Logging   │  ← database/db_manager.py
└─────────────────────┘
```

### Detection Capabilities

The NLP threat detector identifies:

1. **Phishing Patterns**
   - "Verify account", "Confirm identity", "Account suspended"
   - Urgency language ("Act now", "Expires today")
   - Credential requests

2. **Social Engineering**
   - "You have won", "Claim your prize", "Free money"
   - Lottery scams, inheritance schemes
   - Work-from-home offers

3. **Financial Scams**
   - Wire transfer requests
   - Gift card payments
   - Cryptocurrency investments
   - "Send money", "Processing fee"

4. **Suspicious URLs**
   - URL shorteners (bit.ly, tinyurl)
   - Free domains (.tk, .ml, .ga)
   - IP addresses
   - Login/verify domains

5. **Malware Indicators**
   - "Ransomware", "Virus", "Trojan"
   - "Keylogger", "Backdoor", "Exploit"

## Performance Considerations

### Resource Usage

- **CPU**: ~2-5% during scans (brief spikes)
- **Memory**: ~50-100 MB for OCR processing
- **Disk**: Minimal (logs only)

### Optimization Tips

1. **Increase Scan Interval**: Set to 5-10 seconds for lower CPU usage
2. **Lower Sensitivity**: Use LOW or MEDIUM sensitivity
3. **Close When Not Needed**: Stop protection during gaming or video streaming
4. **Monitor Performance**: Check Task Manager for "CyberGuardPro.exe"

## Troubleshooting

### "PIL or Tesseract OCR not available"

**Solution**: Install missing dependencies
```bash
pip install Pillow pytesseract
```
Then install Tesseract OCR system package (see Requirements section)

### "Feature Unavailable" Error

**Cause**: Required dependencies not installed

**Solution**:
1. Verify Pillow: `python -c "from PIL import Image; print('OK')"`
2. Verify pytesseract: `python -c "import pytesseract; print('OK')"`
3. Verify Tesseract OCR: `tesseract --version` (in terminal)

### Tesseract Not Found Error

**Windows Solution**:
```python
# Add to core/realtime_protection.py after imports
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
```

### High CPU Usage

**Solutions**:
- Increase scan interval to 5-7 seconds
- Lower threat sensitivity to LOW
- Stop protection during intensive tasks
- Close other background applications

### False Positives

**Solutions**:
- Lower sensitivity from HIGH to MEDIUM or LOW
- Add trusted domains to whitelist (future feature)
- Review alert details before taking action

### No Threats Detected (Testing)

**Test the Feature**:
1. Open a text editor or browser
2. Type phishing keywords: "Verify your account immediately"
3. Or: "You have won $1,000,000! Click here now"
4. Wait for next scan cycle (3-5 seconds)
5. Alert should appear if sensitivity is set correctly

## Security & Privacy

### Data Privacy

- **Screen captures are NOT saved** - Only text is extracted and analyzed
- **No data sent to external servers** - All processing is local
- **Logs stored locally** - In encrypted SQLite database
- **No personal data collection** - Only threat patterns logged

### What Gets Logged

- Timestamp of detection
- Threat level and confidence score
- Detected patterns (e.g., "Phishing Indicators")
- Sample text (first 200 characters)
- User action taken (Dismiss/Block)

### What Does NOT Get Logged

- Full screen images
- Personal passwords or credentials
- Banking information
- Complete screen text

## FAQ

**Q: Does this record my screen?**  
A: No, it only captures screenshots temporarily for text extraction. Images are not saved.

**Q: Can it detect threats in images/videos?**  
A: Only text-based threats. It extracts visible text using OCR but doesn't analyze images themselves.

**Q: Will it slow down my computer?**  
A: Minimal impact. Brief CPU spikes during scans, but optimized for performance.

**Q: Does it work offline?**  
A: Yes, completely offline. No internet connection required.

**Q: Can I whitelist trusted websites?**  
A: API exists but not yet exposed in UI. Will be added in future updates.

**Q: What if I get too many false alerts?**  
A: Lower the sensitivity to MEDIUM or LOW in settings.

**Q: Does it work with multiple monitors?**  
A: Yes, it captures all visible screens.

**Q: Can it run in the background?**  
A: Yes, it runs as a background thread. Minimize CyberGuard Pro and it continues monitoring.

## Best Practices

1. **Start with MEDIUM sensitivity** - Adjust based on your needs
2. **Review alerts carefully** - Don't ignore warnings
3. **Keep Tesseract updated** - Better OCR accuracy
4. **Monitor performance** - Adjust interval if CPU usage is high
5. **Don't rely solely on this** - Use in combination with other security practices
6. **Test regularly** - Verify it's working by typing phishing keywords
7. **Update threat patterns** - Keep CyberGuard Pro updated

## Support

For issues or questions:
- Check logs: `logs/cyberguard.log`
- Review database: `cyberguard.db` (system_events and threat_logs tables)
- Report bugs: Create an issue with error details

## Future Enhancements

Planned features:
- [ ] Whitelist management UI
- [ ] Custom threat pattern definitions
- [ ] Screenshot saving option (with user consent)
- [ ] Multi-language OCR support
- [ ] Browser extension integration
- [ ] Email content scanning
- [ ] Real-time network traffic analysis
- [ ] Machine learning threat detection

## Version History

- **v1.0** (2025-11-07): Initial Real-Time Protection release
  - Screen capture and OCR
  - NLP-based threat detection
  - Popup alerts with recommended actions
  - Configurable scan interval and sensitivity
  - Database logging and statistics
