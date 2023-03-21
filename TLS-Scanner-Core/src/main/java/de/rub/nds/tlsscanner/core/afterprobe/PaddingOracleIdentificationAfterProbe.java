/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Objects;

public class PaddingOracleIdentificationAfterProbe<Report extends TlsScanReport>
        extends AfterProbe<Report> {

    private PaddingOracleAttributor attributor;

    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    @Override
    public void analyze(Report report) {
        if (Objects.equals(
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                TestResults.TRUE)) {
            KnownPaddingOracleVulnerability knownVulnerability =
                    attributor.getKnownVulnerability(report.getPaddingOracleTestResultList());
            report.setKnownPaddingOracleVulnerability(knownVulnerability);
        }
    }
}
