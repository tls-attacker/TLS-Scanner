/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.probe.padding.PaddingOracleAttributor;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.Objects;

/**
 *
 * @author ic0ns
 */
public class PaddingOracleIdentificationAfterProbe extends AfterProbe {

    private PaddingOracleAttributor attributor;

    public PaddingOracleIdentificationAfterProbe() {
        attributor = new PaddingOracleAttributor();
    }

    @Override
    public void analyze(SiteReport report) {
        if (Objects.equals(report.getPaddingOracleVulnerable(), Boolean.TRUE)) {
            KnownPaddingOracleVulnerability knownVulnerability = attributor.getKnownVulnerability(report.getPaddingOracleTestResultList());
            report.setKnownVulnerability(knownVulnerability);
        }
    }
}
