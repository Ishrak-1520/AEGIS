# Real-Time Protection - Quick Start Guide

## 🚀 Quick Installation (5 Minutes)

### Step 1: Install Python Dependencies
```bash
pip install Pillow pytesseract
```

### Step 2: Install Tesseract OCR (Windows)

**Option A: Automatic Download**
1. Visit: https://github.com/UB-Mannheim/tesseract/wiki
2. Download: `tesseract-ocr-w64-setup-5.3.3.exe` (or latest version)
3. Run the installer
4. Use default installation path: `C:\Program Files\Tesseract-OCR\`

**Option B: Direct Link**
- 64-bit: https://digi.bib.uni-mannheim.de/tesseract/tesseract-ocr-w64-setup-5.3.3.20231005.exe

### Step 3: Verify Installation
```bash
python check_rtp_dependencies.py
```

You should see all checks pass ✓

### Step 4: Run CyberGuard Pro
```bash
python main.py
```

### Step 5: Enable Real-Time Protection
1. Log in to CyberGuard Pro
2. Go to **Overview** tab
3. Click **"▶ Start Real-Time Protection"** button
4. You're protected! 🛡️

---

## 🧪 Test It Works

1. Keep Real-Time Protection active
2. Open Notepad or any text editor
3. Type: `"URGENT: Your account will be suspended! Verify now!"`
4. Wait 3-5 seconds
5. You should see a threat alert popup! 🚨

---

## ⚙️ Configuration

Click **"⚙️ Configure Settings"** to adjust:

### Scan Interval
- **Fast (1-2s)**: More protection, higher CPU usage
- **Balanced (3-5s)**: Recommended for most users ✓
- **Slow (6-10s)**: Lower CPU, delayed detection

### Threat Sensitivity
- **LOW**: Only critical/high threats (fewer alerts)
- **MEDIUM**: Most threats (recommended) ✓
- **HIGH**: All threats including low-risk (more alerts)

---

## 🎯 What It Protects Against

✅ **Phishing Emails/Messages**
- "Verify your account"
- "Confirm your identity"
- "Account suspended"

✅ **Social Engineering**
- "You won a prize!"
- "Free money"
- "Work from home"

✅ **Financial Scams**
- "Send wire transfer"
- "Pay processing fee"
- "Gift card payment"

✅ **Suspicious URLs**
- Shortened URLs (bit.ly, tinyurl)
- Fake login pages
- IP addresses instead of domains

✅ **Malware Indicators**
- "Download virus remover"
- "Ransomware detected"
- "Install this fix"

---

## 📊 Statistics & Monitoring

View real-time stats on the Overview tab:
- **Scans Performed**: Total screen scans
- **Threats Detected**: Number of threats found
- **Status**: Active/Inactive indicator

---

## 🐛 Troubleshooting

### "Feature Unavailable" Error
**Fix:** Install missing dependencies
```bash
pip install Pillow pytesseract
```
Then install Tesseract OCR system package

### "Tesseract not found" Error
**Fix:** Add Tesseract to PATH or configure manually

Run the auto-configuration script:
```bash
python configure_tesseract.py
```

Or manually add to `core/realtime_protection.py`:
```python
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
```

### High CPU Usage
**Fix:** Increase scan interval
1. Click "⚙️ Configure Settings"
2. Set Scan Interval to 5-7 seconds
3. Click OK

### Too Many Alerts
**Fix:** Lower sensitivity
1. Click "⚙️ Configure Settings"
2. Set Threat Sensitivity to LOW or MEDIUM
3. Click OK

---

## 💡 Pro Tips

1. **Test First**: Try it with test phrases to see how it works
2. **Start Conservative**: Use MEDIUM sensitivity initially
3. **Adjust as Needed**: Increase sensitivity if missing threats
4. **Monitor Performance**: Check Task Manager if computer slows down
5. **Stop When Gaming**: Disable during games/videos to save resources

---

## 📖 More Information

- **Detailed Setup**: See `REALTIME_PROTECTION_SETUP.md`
- **Implementation Details**: See `RTP_IMPLEMENTATION_SUMMARY.md`
- **Test Suite**: Run `python test_realtime_protection.py`

---

## ✅ Checklist

Before using Real-Time Protection:

- [ ] Python dependencies installed (`Pillow`, `pytesseract`)
- [ ] Tesseract OCR installed (system package)
- [ ] Dependencies verified (`check_rtp_dependencies.py` passes)
- [ ] CyberGuard Pro running
- [ ] Logged in to application
- [ ] Real-Time Protection started

All checked? You're ready! 🎉

---

## 🆘 Support

If you encounter issues:
1. Run: `python check_rtp_dependencies.py`
2. Check logs: `logs/cyberguard.log`
3. Review threat logs in dashboard (Logs tab)

---

**Enjoy enhanced protection! 🛡️**
