/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import de.rub.nds.scanner.core.report.ScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class GuidelineCheck<R extends ScanReport<R>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private String name;

    private RequirementLevel requirementLevel;

    private GuidelineCheckCondition condition;

    private GuidelineCheck() {}

    public GuidelineCheck(String name, RequirementLevel requirementLevel) {
        this(name, requirementLevel, null);
    }

    public GuidelineCheck(
            String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        this.name = name;
        this.requirementLevel = requirementLevel;
        this.condition = condition;
    }

    public abstract GuidelineCheckResult evaluate(R report);

    public boolean passesCondition(R report) {
        return this.passesCondition(report, this.condition);
    }

    private boolean passesCondition(R report, GuidelineCheckCondition condition) {
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
        LOGGER.warn("Invalid condition object.");
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
