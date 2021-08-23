/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class GuidelineChecker {

    protected static final Logger LOGGER = LogManager.getLogger(GuidelineChecker.class.getName());

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
            GuidelineCheckResult result;
            if (!check.passesCondition(report)) {
                result = new GuidelineCheckResult(null) {
                    @Override
                    public String display() {
                        return "Condition was not met => Check is skipped.";
                    }
                };
                result.setName(check.getName());
                result.setId(check.getId());
                result.setCondition(check.getCondition());
                skipped.add(result);
                continue;
            }
            try {
                result = check.evaluate(report);
            } catch (Throwable throwable) {
                LOGGER.debug("Failed evaluating check: ", throwable);
                result = new GuidelineCheckResult(TestResult.ERROR_DURING_TEST) {
                    @Override
                    public String display() {
                        return throwable.getLocalizedMessage();
                    }
                };
            }

            if (result.getResult() == null) {
                LOGGER.error("Null result from check {}", check.getId());
                continue;
            }
            if (check.getRequirementLevel().equals(RequirementLevel.MAY)) {
                result.setResult(TestResult.TRUE);
            } else if (check.getRequirementLevel().name().contains("NOT")) {
                if (result.getResult().equals(TestResult.TRUE)) {
                    result.setResult(TestResult.FALSE);
                } else if (result.getResult().equals(TestResult.FALSE)) {
                    result.setResult(TestResult.TRUE);
                }
            }
            result.setName(check.getName());
            result.setId(check.getId());
            results.add(result);
        }
        guidelineReports.add(new GuidelineReport(this.guideline.getName(), this.guideline.getLink(), results, skipped));
    }
}
