/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class GuidelineCheck {

    private String name;
    private RequirementLevel requirementLevel;
    private GuidelineCheckCondition condition;

    private GuidelineCheck() {
    }

    public GuidelineCheck(String name, RequirementLevel requirementLevel) {
        this(name, requirementLevel, null);
    }

    public GuidelineCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        this.name = name;
        this.requirementLevel = requirementLevel;
        this.condition = condition;
    }

    public abstract GuidelineCheckResult evaluate(SiteReport report);

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

    public String getName() {
        return name;
    }

    public RequirementLevel getRequirementLevel() {
        return requirementLevel;
    }

    public abstract String getId();

    public GuidelineCheckCondition getCondition() {
        return condition;
    }
}
