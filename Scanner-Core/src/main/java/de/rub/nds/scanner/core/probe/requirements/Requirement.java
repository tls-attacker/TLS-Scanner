/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;

public abstract class Requirement {
    protected Requirement next = Requirement.NO_REQUIREMENT;
    public static BaseRequirement NO_REQUIREMENT = new BaseRequirement();

    protected abstract boolean evaluateIntern(ScanReport report);

    public boolean evaluate(ScanReport report) {
        return next.evaluate(report) && evaluateIntern(report);
    }

    public Requirement requires(Requirement next) {
        next.next = this;
        return next;
    }

    public Requirement getMissingRequirements(ScanReport report) {
        Requirement missing = NO_REQUIREMENT;
        return getMissingRequirementIntern(missing, report);
    }

    public Requirement getNext() {
        return next;
    }

    public abstract Requirement getMissingRequirementIntern(Requirement missing, ScanReport report);

    public static class BaseRequirement extends Requirement {
        @Override
        protected boolean evaluateIntern(ScanReport report) {
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
    }
}
