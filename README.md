# ULTIMATE CREDENTIAL EXTRACTOR

**Defensive Research Tool for Security Analysis and Threat Intelligence**

## ⚠️ LEGAL DISCLAIMER

**This tool is for AUTHORIZED security research, penetration testing, and defensive analysis ONLY.** Use only on:
- Systems you own
- Systems you have explicit written permission to test
- Simulated lab environments
- Educational purposes in controlled settings

**Unauthorized use is illegal and punishable by law.** Always follow applicable regulations (GDPR, HIPAA, etc.) and obtain proper authorization before testing.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [Corporate Email Analysis](#corporate-email-analysis)
- [Output Files](#output-files)
- [Logging](#logging)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## 📖 Overview

The Ultimate Credential Extractor is a sophisticated defensive research tool designed for security professionals, penetration testers, and threat intelligence analysts. It enables:

1. **Credential Analysis**: Extract and analyze credentials from leaked databases, stealer logs, and security dumps
2. **Corporate Risk Assessment**: Identify corporate email credentials with executive detection
3. **Batch Processing**: Handle multiple files simultaneously with progress tracking
4. **Defensive Research**: Support security hardening and credential exposure assessments

## ✨ Features

### Core Features
- **Dual Extraction Modes**: Email:password and username:password extraction
- **Batch Processing**: Process entire folders of log files
- **Keyword Filtering**: Extract credentials by service (Microsoft, PayPal, Amazon, etc.)
- **Progress Tracking**: Real-time progress bars with ETA and speed metrics
- **Duplicate Removal**: Automatically removes duplicate credentials
- **Threaded Processing**: Multi-threaded for high-performance processing

### Advanced Features
- **Corporate Email Detection**: Identifies corporate vs. personal emails
- **Executive Email Detection**: Flags potential executive accounts (CEO, CTO, etc.)
- **Risk Assessment**: Calculates corporate credential exposure risk levels
- **Domain Analysis**: Groups credentials by corporate domain
- **Extraction History**: Maintains session history for audit trails
- **Export Functions**: Export configurations and analysis reports

### Security Features
- **Comprehensive Logging**: Detailed operation logging
- **Isolated Processing**: Safe credential handling
- **Metadata Headers**: Output files include usage disclaimers
- **Data Validation**: Strict validation of extracted credentials

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 1GB free disk space

### Quick Installation
```bash
# 1. Download the script
git clone [repository-url] credential-extractor
cd credential-extractor

# 2. (Optional) Create virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux/Mac:
source venv/bin/activate

# 3. Install dependencies (no external dependencies required)
# The script uses only Python standard library
```

### File Structure
```
credential-extractor/
├── ultimate_credential_extractor.py  # Main script
├── README.md                         # This documentation
├── DATA/                             # Default input folder (create if needed)
├── config.json                       # Configuration file (auto-generated)
└── extractor.log                     # Log file (auto-generated)
```

## 📖 Usage Guide

### Starting the Tool
```bash
python ultimate_credential_extractor.py
```

You'll see the legal disclaimer and main menu:
```
╔════════════════════════════════════════════════════════════════╗
║                 ULTIMATE CREDENTIAL EXTRACTOR                 ║
║                    DEFENSIVE RESEARCH TOOL                    ║
╚════════════════════════════════════════════════════════════════╝

1. Process single file
2. Process DATA folder (multiple files)
3. Manage keywords
4. View extraction history
5. Corporate email analysis
6. Export configuration
7. Exit program
```

### 1. Single File Processing
**Use case**: Analyze a single log file or dump
```bash
Select option: 1

🔧 SINGLE FILE PROCESSING MODE
1. Extract email:pass combinations
2. Extract user:pass combinations
3. Return to main menu
```

**Example workflow**:
```
1. Select mode (1 for email:pass)
2. Select keywords to filter (0 for all, or comma-separated numbers)
3. Enter file path: ./leak_dump.txt
4. Wait for processing
5. View results summary
```

### 2. Folder Processing
**Use case**: Process multiple files in a directory
```bash
Select option: 2

📁 FOLDER PROCESSING MODE
1. Extract email:pass combinations
2. Extract user:pass combinations
3. Return to main menu
```

**Example workflow**:
```
1. Select mode (1 for email:pass)
2. Select keywords
3. Enter folder path (default: ./DATA)
4. Review discovered files
5. Confirm processing
6. Monitor batch progress
7. Review aggregated results
```

### 3. Keyword Management
Manage service-specific keywords for filtering:
```bash
📋 CURRENT KEYWORDS:
1. microsoft
2. paypal
3. amazon
4. netflix
5. spotify
6. google

1. Add new keyword
2. Remove keyword
3. Import keywords from file
4. Export keywords to file
5. Clear all keywords
6. Return to main menu
```

### 4. Corporate Email Analysis
**Use case**: Identify corporate credential exposure risks
```bash
🏢 CORPORATE EMAIL ANALYSIS
1. Analyze existing extraction results
2. Scan folder for corporate credentials
3. Add custom corporate domains
4. View corporate domain database
5. Return to main menu
```

### 5. Export Configuration
Save your current setup for future sessions:
```bash
Enter config export path (default: extractor_config.json)
```

## ⚙️ Configuration

### Default Keywords
The tool comes with predefined keywords for common services:
- `microsoft` - Microsoft accounts
- `paypal` - PayPal accounts
- `amazon` - Amazon accounts
- `netflix` - Netflix accounts
- `spotify` - Spotify accounts
- `google` - Google accounts

### Adding Custom Keywords
```bash
# From the keyword management menu:
Select option: 1
Enter new keyword: github
✅ Keyword 'github' added successfully!
```

### Import/Export Keywords
```bash
# Export current keywords to file
Select option: 4
Enter output file path: my_keywords.txt

# Import keywords from file (one per line)
Select option: 3
Enter keywords file path: service_keywords.txt
```

## 🏢 Corporate Email Analysis

### How It Works
The corporate email detector uses multiple heuristics:

1. **Domain Analysis**: Identifies corporate vs. personal domains
2. **Executive Detection**: Flags potential executive accounts using patterns:
   - `first.last@company.com`
   - `ceo@company.com`, `cto@company.com`, etc.
   - Titles in usernames: `admin`, `director`, `manager`

### Personal Domain Database
The tool recognizes common personal email domains:
```
gmail.com, yahoo.com, hotmail.com, outlook.com, aol.com,
icloud.com, protonmail.com, mail.com, yandex.com, live.com
```

### Risk Assessment Levels
- **CRITICAL**: Executive accounts detected
- **HIGH**: Corporate credential ratio > 30%
- **MEDIUM**: Corporate credential ratio > 10%
- **LOW**: Corporate credential ratio ≤ 10%

### Corporate Scan Workflow
```bash
1. Select "Corporate email analysis" from main menu
2. Choose "Scan folder for corporate credentials"
3. Enter folder path
4. Monitor scanning progress
5. Review risk assessment report
6. Check output files:
   - Corporate_Credentials_Analysis_TIMESTAMP.txt
   - Executive_Credentials_HIGH_RISK_TIMESTAMP.txt
   - Corporate_Analysis_Report_TIMESTAMP.txt
```

## 📄 Output Files

### Single File Extraction
```
microsoft_extracted_email_pass_1678901234.txt
├── # Credential Extraction Results - MICROSOFT
├── # Generated: Fri Mar 15 14:30:00 2024
├── # Total entries: 1,234
├── # Format: login:password
├── # Source keyword: microsoft
├── # Extraction type: SINGLE
├── # FOR AUTHORIZED RESEARCH ONLY
└── user@example.com:Password123
```

### Batch Extraction
```
microsoft_Batch_Extracted_1678901234.txt
├── # BATCH Credential Extraction Results - MICROSOFT
├── # Generated: Fri Mar 15 14:30:00 2024
├── # Total entries: 5,678
├── # Format: login:password
├── # Source keyword: microsoft
├── # Extraction type: BATCH (Multiple Files)
├── # FOR AUTHORIZED RESEARCH ONLY
└── user@example.com:Password123
```

### Corporate Analysis Files
1. **Corporate_Credentials_Analysis_TIMESTAMP.txt** - All corporate credentials grouped by domain
2. **Executive_Credentials_HIGH_RISK_TIMESTAMP.txt** - Executive accounts only
3. **Corporate_Analysis_Report_TIMESTAMP.txt** - Detailed analysis report

## 📝 Logging

### Log File: `extractor.log`
```
2024-03-15 14:30:00,123 - INFO - Starting extraction: mode=email_pass, keywords=['microsoft'], file=./data.txt
2024-03-15 14:30:05,456 - INFO - Processed data.txt: 1,234 credentials
2024-03-15 14:30:06,789 - INFO - Saved 1,234 unique microsoft results to microsoft_extracted_email_pass_1678901234.txt
```

### Console Output
Real-time progress bars show:
- Progress percentage
- Lines processed per second
- Estimated time remaining
- File statistics

## 🔒 Best Practices

### Security Considerations
1. **Isolation**: Run in isolated virtual machines or containers
2. **Network Isolation**: Disconnect from production networks during processing
3. **Data Handling**: Encrypt sensitive output files
4. **Access Control**: Restrict access to extraction results
5. **Data Disposal**: Securely delete output files after analysis

### Ethical Guidelines
1. **Authorization**: Always obtain written permission
2. **Scope Limitation**: Test only within authorized boundaries
3. **Data Minimization**: Only extract necessary information
4. **Reporting**: Document findings for defensive improvements
5. **Responsible Disclosure**: Report vulnerabilities to appropriate parties

### Performance Optimization
1. **File Size**: Works best with files under 10GB
2. **Memory**: Larger files require more RAM (1GB per 10 million lines)
3. **Storage**: Ensure sufficient disk space for output files
4. **CPU**: Multi-threaded processing benefits from more cores

## 🐛 Troubleshooting

### Common Issues

**Issue**: "File not found" error
**Solution**: Use absolute paths or ensure file is in working directory

**Issue**: No credentials extracted
**Solution**: 
1. Check file format (should contain URL:email:password patterns)
2. Verify keywords match content
3. Check file encoding (tool handles UTF-8 and ignores errors)

**Issue**: Slow processing
**Solution**:
1. Close other applications
2. Use SSD storage
3. Process smaller batches
4. Increase chunk size in code (chunk_size variable)

**Issue**: Memory errors with large files
**Solution**:
1. Process files individually instead of batch
2. Increase system RAM
3. Use 64-bit Python

### Error Messages
- `Error counting lines: [error]` - File access/permission issue
- `Error processing file: [error]` - File corruption or encoding issue
- `Error saving results: [error]` - Disk full or permission issue

## ❓ FAQ

**Q: Can this tool extract from encrypted files?**
A: No, the tool only processes plaintext files. Decrypt files first if needed.

**Q: What file formats are supported?**
A: All plaintext formats: .txt, .log, .csv, .data, and similar

**Q: Is there a limit on file size?**
A: No hard limit, but performance depends on available RAM

**Q: Can I add custom regex patterns?**
A: Yes, modify the `credential_patterns` list in the `extract_credential` method

**Q: How are duplicates handled?**
A: Duplicates are removed while preserving order during output file creation

**Q: Can I use this for password auditing?**
A: Yes, but ensure you have authorization to test the passwords

**Q: Is there a command-line interface?**
A: Currently only interactive menu mode is available

**Q: Can I integrate this into other tools?**
A: Yes, the classes can be imported and used programmatically

## 📊 Example Workflows

### Workflow 1: Basic Credential Extraction
```bash
1. python ultimate_credential_extractor.py
2. Accept legal disclaimer
3. Select "Process single file"
4. Choose "Extract email:pass combinations"
5. Select keywords (0 for all)
6. Enter file path: ./leaked_data.txt
7. Review results summary
8. Check generated output files
```

### Workflow 2: Corporate Risk Assessment
```bash
1. python ultimate_credential_extractor.py
2. Select "Process DATA folder"
3. Choose "Extract email:pass combinations"
4. Select all keywords (0)
5. Enter folder path: ./breach_dumps/
6. Confirm processing
7. After extraction, select "Corporate email analysis"
8. Choose "Analyze existing extraction results"
9. Review risk assessment report
10. Check executive credentials file
```

### Workflow 3: Service-Specific Analysis
```bash
1. python ultimate_credential_extractor.py
2. Select "Manage keywords"
3. Add service-specific keywords: github, twitter, facebook
4. Return to main menu
5. Select "Process DATA folder"
6. Choose specific keywords (e.g., 1,3,5 for microsoft, amazon, netflix)
7. Monitor extraction progress
8. Export results for each service
```

## 🔧 Advanced Customization

### Modifying Detection Patterns
Edit these sections in the code:

1. **Corporate detection**: Modify `CorporateEmailDetector` class
2. **Credential patterns**: Update `credential_patterns` in `extract_credential` method
3. **Email validation**: Adjust `is_valid_email` method
4. **Progress display**: Modify `ProgressBar` class

### Adding New Output Formats
Extend the `save_per_keyword_results` method to support:
- JSON output
- CSV format
- Database storage
- Encrypted output

### Performance Tuning
Adjust these variables:
- `chunk_size` in `process_file` method (default: 10000)
- `max_workers` in ThreadPoolExecutor (default: min(8, cpu_count))
- Progress update frequency in `ProgressBar.update` method

## 📞 Support

### Reporting Issues
1. Check the troubleshooting section
2. Review the extractor.log file
3. Ensure Python 3.8+ is installed
4. Verify file permissions

### Feature Requests
Common requested features:
- Command-line interface
- Database output support
- API integration
- GUI interface
- Cloud storage integration

## 📜 License and Attribution

### License
This tool is provided for educational and authorized security research purposes only. Users are responsible for complying with all applicable laws and regulations.

### Attribution
If you use this tool in research or publications, please credit appropriately.

### Updates
Regular updates include:
- New credential patterns
- Additional corporate domains
- Performance improvements
- Security enhancements

---

**Remember**: With great power comes great responsibility. Use this tool ethically, legally, and only for defensive security purposes.


*Last updated: NOVEMBER 2025*
