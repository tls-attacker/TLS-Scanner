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
import java.util.ArrayList;
import java.util.List;

public class OrRequirement extends Requirement {
    private final Requirement[] requirements;
    private List<Requirement> missing;

    public OrRequirement(Requirement... requirements) {
        super();
        this.requirements = requirements;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if (requirements == null || requirements.length == 0)
            return true;
        boolean returnValue = false;
        missing = new ArrayList<>();
        for (Requirement req : requirements) {
            if (req.evaluate(report))
                returnValue = true;
            else
                missing.add(req);
        }
        return returnValue;
    }

    /**
     * @return the or requirements
     */
    public Requirement[] getRequirement() {
        return requirements;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false)
            return next.getMissingRequirementIntern(
                missing.requires(new OrRequirement(this.missing.toArray(new Requirement[this.missing.size()]))),
                report);
        return next.getMissingRequirementIntern(missing, report);
    }
}
