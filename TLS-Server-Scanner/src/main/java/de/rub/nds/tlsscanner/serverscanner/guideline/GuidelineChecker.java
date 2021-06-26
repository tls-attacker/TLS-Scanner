/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.ArrayList;
import java.util.List;

public class GuidelineChecker {

    private final Guideline guideline;

    public GuidelineChecker(Guideline guideline) {
        this.guideline = guideline;
    }

    public void fillReport(SiteReport report) {
        List<GuidelineReport> guidelineReports = report.getGuidelineReports();
        if (guidelineReports == null) {
            guidelineReports = new ArrayList<>();
            report.setGuidelineReports(guidelineReports);
        }
        List<GuidelineCheckResult> results = new ArrayList<>();
        List<GuidelineCheckResult> skipped = new ArrayList<>();
        for (GuidelineCheck check : this.guideline.getChecks()) {
            GuidelineCheckResult result = new GuidelineCheckResult(check.getName());
            if (check instanceof ConditionalGuidelineCheck) {
                if (((ConditionalGuidelineCheck) check).passesCondition(report)) {
                    check.evaluate(report, result);
                } else {
                    result.append("Condition was not met => Check is skipped.");
                }
            } else {
                check.evaluate(report, result);
            }
            if (result.getStatus() != null) {
                if (check.getRequirementLevel().equals(RequirementLevel.MAY)) {
                    result.setStatus(GuidelineCheckStatus.PASSED);
                }
                if (check.getRequirementLevel().name().contains("NOT")) {
                    if (result.getStatus().equals(GuidelineCheckStatus.PASSED)) {
                        result.setStatus(GuidelineCheckStatus.FAILED);
                    } else if (result.getStatus().equals(GuidelineCheckStatus.FAILED)) {
                        result.setStatus(GuidelineCheckStatus.PASSED);
                    }
                }
                results.add(result);
            } else {
                skipped.add(result);
            }
        }
        guidelineReports.add(new GuidelineReport(this.guideline.getName(), this.guideline.getLink(), results, skipped));
    }
}
