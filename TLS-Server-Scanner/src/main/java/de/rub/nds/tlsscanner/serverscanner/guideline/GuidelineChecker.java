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
        List<GuidelineCheckResult> results = new ArrayList<>(this.guideline.getChecks().size());
        for (GuidelineCheck check : this.guideline.getChecks()) {
            results.add(check.evaluate(report));
        }
        guidelineReports.add(new GuidelineReport(this.guideline.getName(), this.guideline.getLink(), results));
    }
}
