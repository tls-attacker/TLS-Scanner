/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

public abstract class TlsGuidelineCheck extends GuidelineCheck {

    public TlsGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public TlsGuidelineCheck(
            String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        super(name, requirementLevel, condition);
    }

    @Override
    public <ReportT extends ScanReport> GuidelineCheckResult evaluate(ReportT report) {
        if (report instanceof TlsScanReport) {
            return evaluate((TlsScanReport) report);
        }
        throw new RuntimeException(
                "The report has to be of type TlsScanReport, but was: "
                        + report.getClass().getName());
    }

    @Override
    public <ReportT extends ScanReport> boolean passesCondition(ReportT report) {
        if (report instanceof TlsScanReport tlsScanReport) {
            return passesCondition(tlsScanReport);
        }
        return super.passesCondition(report);
    }

    public boolean passesCondition(TlsScanReport report) {
        return super.passesCondition(report);
    }

    public abstract GuidelineCheckResult evaluate(TlsScanReport report);
}
