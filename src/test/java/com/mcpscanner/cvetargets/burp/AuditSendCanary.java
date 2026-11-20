package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.AuditPathCanaryCommand;
import com.mcpscanner.automation.AuditPathCanaryReport;

interface AuditSendCanary {

    AuditPathCanaryReport auditPathCanary(AuditPathCanaryCommand command);
}
