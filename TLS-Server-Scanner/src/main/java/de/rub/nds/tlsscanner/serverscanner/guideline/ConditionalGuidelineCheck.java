/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public abstract class ConditionalGuidelineCheck extends GuidelineCheck {

    private GuidelineCheckCondition condition;

    public boolean passesCondition(SiteReport report) {
        return this.passesCondition(report, this.condition);
    }

    private boolean passesCondition(SiteReport report, GuidelineCheckCondition condition) {
        if (condition == null) {
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
        ConsoleLogger.CONSOLE.warn("Invalid condition object.");
        return false;
    }

    public GuidelineCheckCondition getCondition() {
        return condition;
    }

    public void setCondition(GuidelineCheckCondition condition) {
        this.condition = condition;
    }
}
