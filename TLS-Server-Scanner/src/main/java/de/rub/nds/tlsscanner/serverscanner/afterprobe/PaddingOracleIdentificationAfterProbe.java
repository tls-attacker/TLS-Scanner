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
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Objects;

public class PaddingOracleIdentificationAfterProbe extends AfterProbe<ServerReport> {

    private PaddingOracleAttributor attributor;

    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    @Override
    public void analyze(ServerReport report) {
        if (Objects.equals(report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE), TestResult.TRUE)) {
            KnownPaddingOracleVulnerability knownVulnerability =
                attributor.getKnownVulnerability(report.getPaddingOracleTestResultList());
            report.setKnownVulnerability(knownVulnerability);
        }
    }
}
