/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingOracleIdentificationAfterProbe extends AfterProbe<ServerReport> {

    private PaddingOracleAttributor attributor;
    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    @Override
    public void analyze(ServerReport report) {
        if (Objects.equals(report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE), TestResults.TRUE)) {
            try {
                @SuppressWarnings("unchecked")
                KnownPaddingOracleVulnerability knownVulnerability =
                    attributor.getKnownVulnerability(((ListResult<InformationLeakTest<PaddingOracleTestInfo>>) report
                        .getListResult(TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULT.name())).getList());
                report.setKnownVulnerability(knownVulnerability);
            } catch (Exception e) {
                LOGGER.debug("property " + TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULT.name()
                    + " requires a TestResult for the PaddingOracleIdentificationAfterProbe but probably has result null!"
                    + e.getMessage());
            }
        }
    }
}
