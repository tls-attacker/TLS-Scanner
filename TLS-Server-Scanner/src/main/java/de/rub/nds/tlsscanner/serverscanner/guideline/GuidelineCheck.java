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

public abstract class GuidelineCheck {

    private String name;
    private String description;
    private RequirementLevel requirementLevel;

    public abstract void evaluate(SiteReport report, GuidelineCheckResult result);

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
