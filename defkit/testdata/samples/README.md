# Test Samples

This directory contains test samples for signature generation and validation.

## EICAR Test File

The EICAR test file is a standard antivirus test file that is recognized by all major antivirus products as a test signature, but contains no actual malicious code.

**File:** `EICAR.txt`
**Detection Name:** EICAR-AV-Test
**MD5:** 44d88612fea8a8f36de82e1278abb02f
**SHA256:** 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

## Adding Test Samples

To add your own test samples:

1. Place the sample file in this directory
2. Run analysis: `defkit analyze sample.exe -o analysis/`
3. Generate signatures: `defkit generate analysis/sample.json --name ThreatName`

## Safety Notes

- Only add malware samples in controlled, isolated environments
- Never execute samples on production systems
- Keep samples password-protected in archives when possible
- Use standard password "infected" for malware archives
- Document all samples with hash values and descriptions

## Sample Organization

Organize samples by family:

```
samples/
├── ransomware/
│   ├── wannacry.exe
│   └── locky.dll
├── trojans/
│   ├── emotet.exe
│   └── trickbot.dll
└── backdoors/
    └── njrat.exe
```
