/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.LogicRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.ArrayList;

/**
 * Represents a {@link Requirement} that implements a logical or for multiple multiple Requirements.
 * If one of the contained Requirements evaluates to true, this Requirement will evaluate to true.
 */
public class OrRequirement extends LogicRequirement {
    /**
     * @param requirements the {@link Requirement}s which are connected logically with an OR.
     */
    public OrRequirement(Requirement... requirements) {
        super(requirements);
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (parameters == null || parameters.length == 0) {
            return true;
        }
        boolean returnValue = false;
        missingParameters = new ArrayList<>();
        for (Requirement requirement : parameters) {
            if (requirement.evaluate(report)) {
                returnValue = true;
            } else {
                missingParameters.add(requirement);
            }
        }
        return returnValue;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new OrRequirement(
                                    this.missingParameters.toArray(
                                            new Requirement[this.missingParameters.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
