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
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;
import java.util.List;

public class ProbeRequirement extends Requirement {
    private final TlsProbeType[] probes;
    private List<TlsProbeType> missing;

    public ProbeRequirement(TlsProbeType... probes) {
        super();
        this.probes = probes;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if ((probes == null) || (probes.length == 0)) {
            return true;
        }
        boolean returnValue = true;
        missing = new ArrayList<>();
        for (TlsProbeType probe : probes) {
            if (report.isProbeAlreadyExecuted(probe) == false) {
                returnValue = false;
                missing.add(probe);
            }
        }
        return returnValue;
    }

    public TlsProbeType[] getRequirement() {
        return probes;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new ProbeRequirement(
                                    this.missing.toArray(new TlsProbeType[this.missing.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
