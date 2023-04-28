/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Objects;

public class PaddingOracleIdentificationAfterProbe extends AfterProbe<ServerReport> {

    private PaddingOracleAttributor attributor;
    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    @Override
    public void analyze(ServerReport report) {
        if (Objects.equals(
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                TestResults.TRUE)) {
            try {
                KnownPaddingOracleVulnerability knownVulnerability =
                        attributor.getKnownVulnerability(report.getPaddingOracleTestResultList());
                report.setKnownPaddingOracleVulnerability(knownVulnerability);
            } catch (Exception e) {
                LOGGER.debug(
                        "property "
                                + TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT.name()
                                + " requires a TestResult for the PaddingOracleIdentificationAfterProbe but probably has result null!"
                                + e.getMessage());
            }
        }
    }
}
