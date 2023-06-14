/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;

/**
 * Rudimentary Requirement which serves as anchor for Requirement chains and the missing Requirement
 * chains. Evaluates to true and is used as static NO_REQUIREMENT if a probe can be executed without
 * any requirement.
 */
public class BaseRequirement extends Requirement {
    @Override
    public String toString() {
        return "no requirement";
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        return true;
    }

    @Override
    public boolean evaluate(ScanReport report) {
        return true;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        return missing;
    }

    @Override
    public Enum<?>[] getRequirement() {
        return new Enum<?>[0];
    }
}
