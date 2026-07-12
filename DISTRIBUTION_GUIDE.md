# AEGIS Standalone Windows Distribution Guide

This guide explains how to build and distribute AEGIS as a standalone desktop application (`AEGIS.exe`) for free using **GitHub Releases**.

---

## 1. Prerequisites

Ensure your build environment has Python 3.8+ and Node.js installed, along with project dependencies:

```powershell
pip install -r requirements.txt pyinstaller
cd UI/frontend
npm install
cd ../..
```

---

## 2. Building the Standalone Executable

We provide an automated build script (`build_aegis.py`) that packages the Python security daemon, pre-compiled React 19 UI, and YARA rule definitions into a single Windows executable:

### Using PowerShell / Command Prompt:
```powershell
python build_aegis.py
```

### Using Windows Batch Script:
Double-click **`BUILD_AEGIS.bat`** in the project root folder.

Upon successful completion, your standalone executable will be generated at:
```
dist\AEGIS.exe
```

---

## 3. Distributing for Free via GitHub Releases

To share AEGIS with users without any server or hosting costs:

1. Go to your repository on GitHub: [https://github.com/Ishrak-1520/AEGIS](https://github.com/Ishrak-1520/AEGIS)
2. Click on **Releases** on the right sidebar and select **Draft a new release**.
3. Create a tag (for example, `v2.0.0`) and set the release title to **AEGIS v2.0.0 Desktop Release**.
4. Drag and drop `dist\AEGIS.exe` into the **Attach binaries by dropping them here** section.
5. Click **Publish release**.

Users can now download and run `AEGIS.exe` directly on their Windows 10 or 11 endpoints.
