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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ConditionalGuidelineCheck extends GuidelineCheck {

    private final static Logger LOGGER = LoggerFactory.getLogger(ConditionalGuidelineCheck.class);

    private GuidelineCheckCondition condition;

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        return this.passesCondition(report, this.condition) ? super.evaluate(report)
            : new GuidelineCheckResult(this.getName(), this.getDescription(), GuidelineCheckStatus.PASSED);
    }

    private boolean passesCondition(SiteReport report, GuidelineCheckCondition condition) {
        if (condition == null) {
            LOGGER.warn("Conditional Guideline Check does not have condition.");
            return true;
        }
        if (condition.getAnd() != null) {
            for (GuidelineCheckCondition andCondition : condition.getAnd()) {
                if (!this.passesCondition(report, andCondition)) {
                    return false;
                }
            }
            return true;
        } else if (condition.getOr() != null) {
            for (GuidelineCheckCondition orCondition : condition.getOr()) {
                if (this.passesCondition(report, orCondition)) {
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

    public GuidelineCheckCondition getCondition() {
        return condition;
    }

    public void setCondition(GuidelineCheckCondition condition) {
        this.condition = condition;
    }
}
