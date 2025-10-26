# Report Naming Update

## Changes Made

### New Report Naming Convention
Reports are now saved with the new naming format:
```
security_audit_report_YYYYMMDD_HHMMSS.json
```

### Old Format (Still Supported)
The old format is still recognized for backwards compatibility:
```
security_report_YYYYMMDD_HHMMSS.json
```

## Files Updated

1. **`security_auditor/utils/report_generator.py`**
   - Changed report filename generation to use `security_audit_report_` prefix
   - New reports will be named: `security_audit_report_20251026_120000.json`

2. **`security_auditor/dashboard/live_dashboard.py`**
   - Updated to recognize both old and new report naming conventions
   - Automatically loads the newest report regardless of naming
   - Sidebar supports selecting from both old and new reports

3. **`security_auditor/dashboard/security_dashboard.py`**
   - Updated to recognize both old and new report naming conventions
   - Backwards compatible with existing reports

## How It Works Now

### For New Reports
- ✅ All new scans will save as: `security_audit_report_YYYYMMDD_HHMMSS.json`
- ✅ Dashboard automatically shows the newest report
- ✅ Timestamp format: `20251026_143022` (Year, Month, Day, Hour, Minute, Second)

### For Old Reports
- ✅ Old reports still accessible in dashboard
- ✅ Dashboard shows all reports (old + new) in sidebar
- ✅ Old format: `security_report_YYYYMMDD_HHMMSS.json`
- ✅ New format: `security_audit_report_YYYYMMDD_HHMMSS.json`

## Example Report Files

```
reports/
├── security_report_20250925_222920.json        # Old format (still works)
├── security_report_20251026_115206.json        # Old format (still works)
├── security_audit_report_20251026_120000.json  # New format
└── security_audit_report_20251026_143022.json  # New format
```

## Benefits

1. ✅ **Clearer naming** - "security_audit_report" is more descriptive
2. ✅ **Timestamp included** - When the report was created
3. ✅ **Automatic sorting** - Dashboard always shows the newest first
4. ✅ **Backwards compatible** - Old reports still work
5. ✅ **Easy identification** - Can distinguish new vs old reports

## Dashboard Behavior

### Loading Reports
- Dashboard loads the **newest** report by timestamp
- Shows in sidebar: "📌 Latest Report: security_audit_report_XXXX.json"
- You can manually select older reports from dropdown

### Report Selection
- Sidebar shows all available reports (old + new)
- Newest report is automatically selected
- You can switch to any historical report

## Migration Notes

If you deleted old reports and are still seeing them:
- They're still in the file system - check `reports/` and `security_auditor/reports/` directories
- Dashboard only shows files that physically exist
- Delete them from the file system if you want them gone

## Test It

Run a new scan and verify:

```bash
python security_auditor/main.py --mode audit
```

You should see:
```
Report saved: reports/security_audit_report_YYYYMMDD_HHMMSS.json
```

The dashboard will automatically load this newest report!
