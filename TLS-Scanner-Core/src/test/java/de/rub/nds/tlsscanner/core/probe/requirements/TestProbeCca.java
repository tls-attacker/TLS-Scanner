/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/** Test probe class with type CCA. */
public class TestProbeCca<Report extends TlsScanReport> extends ScannerProbe<Report> {

    public TestProbeCca(ProbeType type) {
        super(TlsProbeType.CCA);
    }

    @Override
    public void executeTest() {}

    @Override
    public void adjustConfig(Report report) {}

    @Override
    public Requirement getRequirements() {
        return null;
    }

    @Override
    public void merge(Report report) {}
}
