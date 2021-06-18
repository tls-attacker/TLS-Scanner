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
import org.apache.commons.lang3.tuple.Pair;

public abstract class GuidelineCheck {

    private String name;
    private String description;
    private RequirementLevel requirementLevel;

    public GuidelineCheckResult evaluate(SiteReport report) {
        Pair<GuidelineCheckStatus, String> result = this.evaluateStatus(report);
        GuidelineCheckStatus status = result.getKey();
        if (RequirementLevel.MUST_NOT.equals(requirementLevel)
            || RequirementLevel.SHOULD_NOT.equals(requirementLevel)) {
            // the server must/should not pass this test -> result has to be inverted
            if (GuidelineCheckStatus.PASSED.equals(status)) {
                status = GuidelineCheckStatus.FAILED;
            } else if (GuidelineCheckStatus.FAILED.equals(status)) {
                status = GuidelineCheckStatus.PASSED;
            }
        }
        if (RequirementLevel.MAY.equals(requirementLevel) && GuidelineCheckStatus.FAILED.equals(status)) {
            status = GuidelineCheckStatus.UNCERTAIN;
        }
        return new GuidelineCheckResult(this.name, result.getValue(), status);
    }

    public abstract Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report);

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public RequirementLevel getRequirementLevel() {
        return requirementLevel;
    }

    public void setRequirementLevel(RequirementLevel requirementLevel) {
        this.requirementLevel = requirementLevel;
    }
}
