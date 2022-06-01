/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;

public class OrRequirement extends Requirement {
    private final Requirement[] requirements;

    public OrRequirement(Requirement... requirements) {
        super();
        this.requirements = requirements;
    }

    @Override
    public boolean evaluate(ScanReport report) {
        if (requirements == null || requirements.length == 0)
            return next.evaluate(report);
        for (Requirement req : requirements) {
            if (req.evaluate(report))
                return next.evaluate(report);
        }
        return false;
    }

    /**
     * @return the or requirements
     */
    public Requirement[] getRequirement() {
        return requirements;
    }
}
