/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Objects;

/**
 * AfterProbe implementation that identifies specific known padding oracle vulnerabilities after a
 * padding oracle vulnerability has been detected.
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public class PaddingOracleIdentificationAfterProbe<ReportT extends TlsScanReport>
        extends AfterProbe<ReportT> {

    private PaddingOracleAttributor attributor;

    /**
     * Constructs a new PaddingOracleIdentificationAfterProbe with a PaddingOracleAttributor for
     * identifying known vulnerabilities.
     */
    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    /**
     * Analyzes the report to identify specific known padding oracle vulnerabilities. This method
     * only runs if the report indicates the target is vulnerable to padding oracle attacks. If
     * vulnerable, it uses the PaddingOracleAttributor to determine which known vulnerability is
     * present based on the padding oracle test results.
     *
     * @param report the TLS scan report containing padding oracle test results
     */
    @Override
    public void analyze(ReportT report) {
        if (Objects.equals(
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                TestResults.TRUE)) {
            KnownPaddingOracleVulnerability knownVulnerability =
                    attributor.getKnownVulnerability(report.getPaddingOracleTestResultList());
            report.putResult(
                    TlsAnalyzedProperty.KNOWN_PADDING_ORACLE_VULNERABILITY, knownVulnerability);
        }
    }
}
