# Dashboard Report Loading - How It Works

## ✅ Latest Report Detection

The dashboard now **automatically loads the most recent report** based on the timestamp in the filename, not old reports.

### How It Works:

1. **Timestamp-Based Selection**: 
   - The dashboard parses the timestamp from the filename format: `security_report_YYYYMMDD_HHMMSS.json`
   - Examples: `security_report_20250928_120418.json`, `security_report_20251001_143022.json`

2. **Always Shows Latest**:
   - The dashboard automatically opens the report with the **newest timestamp**
   - After running a new scan, the dashboard will load that report by default
   - Old reports won't be shown unless you manually select them

3. **Cross-Directory Support**:
   - Checks both `reports/` and `security_auditor/reports/` directories
   - Loads the most recent report from either location

### Example Timeline:

```
10:30 AM - Run scan → Creates report: security_report_20251001_103000.json
10:45 AM - Run scan → Creates report: security_report_20251001_104500.json
11:00 AM - Open dashboard → Automatically loads security_report_20251001_104500.json (latest)
```

## Manual Report Selection

If you want to view older reports:

1. Look at the sidebar - it shows "📌 Currently Viewing: [report name]"
2. Use the dropdown "Select Different Report" to choose an older report
3. The latest report is always sorted first in the list

## Benefits

✅ **Always shows the most recent scan results**  
✅ **Automatically updates after new scans**  
✅ **No confusion about which report you're viewing**  
✅ **Easy access to historical reports via sidebar**  
✅ **Platform-independent** (works on Windows, Linux, Mac)

## Technical Details

- Uses filename parsing (not file system timestamps) for reliability
- Sorts reports by timestamp: `YYYYMMDD_HHMMSS` format
- Automatically switches to newest report on dashboard load
- Provides visual indicators in the sidebar showing current report

