/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class GuidelineChecker {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final Guideline guideline;

    public GuidelineChecker(Guideline guideline) {
        this.guideline = guideline;
    }

    public void fillReport(ServerReport report) {
        List<GuidelineReport> guidelineReports = report.getGuidelineReports();
        if (guidelineReports == null) {
            guidelineReports = new ArrayList<>();
        }
        List<GuidelineCheckResult> results = new ArrayList<>();
        for (GuidelineCheck check : guideline.getChecks()) {
            GuidelineCheckResult result;
            if (!check.passesCondition(report)) {
                result =
                        new GuidelineCheckResult(TestResults.COULD_NOT_TEST) {
                            @Override
                            public String display() {
                                return "Condition was not met => Check is skipped.";
                            }
                        };
                result.setName(check.getName());
                result.setId(check.getId());
                result.setCondition(check.getCondition());
                results.add(result);
                continue;
            }
            try {
                result = check.evaluate(report);
            } catch (Throwable throwable) {
                LOGGER.debug("Failed evaluating check: ", throwable);
                result =
                        new GuidelineCheckResult(TestResults.ERROR_DURING_TEST) {
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
            if (Objects.equals(check.getRequirementLevel(), RequirementLevel.MAY)) {
                result.setResult(TestResults.TRUE);
            } else if (Objects.equals(check.getRequirementLevel(), RequirementLevel.MUST_NOT)
                    || Objects.equals(check.getRequirementLevel(), RequirementLevel.SHOULD_NOT)) {
                if (result.getResult().equals(TestResults.TRUE)) {
                    result.setResult(TestResults.FALSE);
                } else if (result.getResult().equals(TestResults.FALSE)) {
                    result.setResult(TestResults.TRUE);
                }
            }
            result.setName(check.getName());
            result.setId(check.getId());
            results.add(result);
        }
        guidelineReports.add(
                new GuidelineReport(this.guideline.getName(), this.guideline.getLink(), results));
        report.putResult(
                TlsAnalyzedProperty.GUIDELINE_REPORTS,
                new ListResult<>(guidelineReports, "GUIDELINE_REPORTS"));
    }
}
