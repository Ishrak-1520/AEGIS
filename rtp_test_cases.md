# Real-Time Protection Threat Scenarios

To test the Real-Time Protection's new context analysis and the OS-level Native Windows Toast popups, simply open this file and display the following blocks of text on your screen while AEGIS Real-Time Protection is running. 

Wait roughly 3 to 5 seconds per test to allow the screen scanner to capture, run keyword matching, and verify with the LLM before moving to the next block.

---

## Test 1: Benign Match (Should NOT Trigger an Alert)
This text contains flagged keywords like "update", "password", and "urgent", but the context is clearly safe. 

**Text to Display on Screen:**
```
Hey team, just a quick reminder about the upcoming server maintenance. It is somewhat urgent that everyone finishes their database update scripts before Friday. Also, remember to change your local test password to the new format we discussed in the sprint planning meeting. Let me know if you need help verifying the new credentials.
```

*Expected Result: No notification. The LLM confirms it is a benign technical discussion despite the keywords.*

---

## Test 2: Credential Harvesting Phishing (Should Trigger an Alert)
This text appears to be a legitimate security threat attempting to trick a user into handing over credentials.

**Text to Display on Screen:**
```
URGENT: Microsoft Account Security Alert
We have detected unusual sign-in activity on your account from a new device in Russia. Your account has been temporarily suspended. To verify your identity and restore access, please click the link below to update your password immediately.
http://secure-microsoft-verify-login-update.com/login

Failure to verify within 24 hours will result in permanent account deletion.
```

*Expected Result: A native Windows OS notification pops up in your bottom-right corner warning you of a High or Critical Threat (Phishing / Credential Harvesting).*

---

## Test 3: Tech Support Scam (Should Trigger an Alert)
This text simulates a fake tech support popup that commonly locks browsers.

**Text to Display on Screen:**
```
*** WINDOWS DEFENDER SECURITY WARNING ***
Your computer has been infected with Trojan.Spyware.Win32.
Do not close this window or restart your computer. Your financial information, Facebook login, and email passwords are at risk of being stolen to a remote server. 

Call Microsoft Technical Support immediately at:
1-888-555-0199

Our certified engineers will guide you through the removal process over the phone.
```

*Expected Result: A native Windows OS notification appears warning you of a High or Critical Threat (Tech Support Scam / Malware Alert).*

---

## Test 4: Benign Software Documentation (Should NOT Trigger an Alert)
This simulates reading a typical software manual or README file.

**Text to Display on Screen:**
```
To install the new security update, navigate to the settings menu and click "Verify Local Files". The system will download the patch and prompt you for the administrator password. This is a standard procedure and is completely safe. If you get a warning about an unverified publisher, you can ignore it as our certificate is still propagating.
```

*Expected Result: No notification. The LLM understands this is software documentation/instruction, not an active threat.*
