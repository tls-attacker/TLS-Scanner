/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a {@link Requirement} that implements a logical or for multiple multiple Requirements.
 * If one of the contained Requirements evaluates to true, this Requirement will evaluate to true.
 */
public class OrRequirement extends Requirement {
    private final Requirement[] requirements;
    private List<Requirement> missing;

    /**
     * @param requirements the Requirements which are connected logically with an OR.
     */
    public OrRequirement(Requirement... requirements) {
        super();
        this.requirements = requirements;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if ((requirements == null) || (requirements.length == 0)) {
            return true;
        }
        boolean returnValue = false;
        missing = new ArrayList<>();
        for (Requirement requirement : requirements) {
            if (requirement.evaluate(report)) {
                returnValue = true;
            } else {
                missing.add(requirement);
            }
        }
        return returnValue;
    }

    /**
     * @return the Requirements which are connected logically with an OR.
     */
    public Requirement[] getRequirement() {
        return requirements;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new OrRequirement(
                                    this.missing.toArray(new Requirement[this.missing.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
