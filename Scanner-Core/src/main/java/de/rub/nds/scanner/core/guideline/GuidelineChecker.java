/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GuidelineChecker<R extends ScanReport<R>> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final Guideline<R> guideline;

    public GuidelineChecker(Guideline<R> guideline) {
        this.guideline = guideline;
    }

    public void fillReport(R report) {
        List<GuidelineReport> guidelineReports = report.getGuidelineReports();
        if (guidelineReports == null) {
            guidelineReports = new ArrayList<>();
        }
        List<GuidelineCheckResult> results = new ArrayList<>();
        for (GuidelineCheck<R> check : guideline.getChecks()) {
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
        report.setGuidelineReports(guidelineReports);
    }
}
