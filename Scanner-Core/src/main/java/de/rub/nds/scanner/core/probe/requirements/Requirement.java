/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;

public abstract class Requirement {
    protected Requirement next = BaseRequirement.NO_REQUIREMENT;

    public abstract boolean evaluate(ScanReport report);

    public Requirement requires(Requirement next) {
        next.next = this;
        return next;
    }

    public static class BaseRequirement extends Requirement {
        public static BaseRequirement NO_REQUIREMENT = new BaseRequirement();

        @Override
        public boolean evaluate(ScanReport report) {
            return true;
        }
    }
}
