/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
