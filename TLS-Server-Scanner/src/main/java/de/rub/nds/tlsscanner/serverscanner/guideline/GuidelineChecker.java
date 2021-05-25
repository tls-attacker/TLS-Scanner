/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 * <p>
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.GuidelineCipherSuites;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class GuidelineChecker {

    private final static Logger LOGGER = LoggerFactory.getLogger(GuidelineCheck.class);

    public List<CipherSuite> getDisallowedSuites(SiteReport report, List<GuidelineCipherSuites> cipherSuites) {
        List<CipherSuite> allowedSuites = new ArrayList<>();
        for (GuidelineCipherSuites guidelineSuites : cipherSuites) {
            if (this.isTrue(report, guidelineSuites.getCondition())) {
                allowedSuites.addAll(guidelineSuites.getCipherSuites());
            }
        }
        return report.getCipherSuites().stream().filter(suite -> !allowedSuites.contains(suite))
                .collect(Collectors.toList());
    }

    public boolean passesCheck(SiteReport report, GuidelineCheck check) {
        if (!this.isTrue(report, check.getCondition())) {
            return true;
        }
        switch (check.getRequirementLevel()) {
            case MUST:
            case SHOULD:
                return check.getResult().equals(report.getResult(check.getAnalyzedProperty()));
            case MUST_NOT:
            case SHOULD_NOT:
                return !check.getResult().equals(report.getResult(check.getAnalyzedProperty()));
            case MAY:
                return true;
            default:
                throw new IllegalArgumentException("Unknown Requirement Level: " + check.getRequirementLevel());
        }
    }

    private boolean isTrue(SiteReport report, GuidelineCheckCondition condition) {
        if (condition == null) {
            return true;
        }
        if (condition.getAnd() != null) {
            for (GuidelineCheckCondition andCondition : condition.getAnd()) {
                if (!this.isTrue(report, andCondition)) {
                    return false;
                }
            }
            return true;
        } else if (condition.getOr() != null) {
            for (GuidelineCheckCondition orCondition : condition.getOr()) {
                if (this.isTrue(report, orCondition)) {
                    return true;
                }
            }
            return false;
        } else if (condition.getAnalyzedProperty() != null && condition.getResult() != null) {
            return condition.getResult().equals(report.getResult(condition.getAnalyzedProperty()));
        }
        LOGGER.warn("Invalid condition object.");
        return false;
    }
}
