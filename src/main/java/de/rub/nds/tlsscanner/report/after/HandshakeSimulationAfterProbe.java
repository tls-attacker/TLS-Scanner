/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.SiteReport;

public class HandshakeSimulationAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        int secureConnectionCounter = 0;
        for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
            if (simulatedClient.getReceivedServerHelloDone()) {
                simulatedClient.setConnectionSecure(true);
                if (report.getPaddingOracleVulnerable() && simulatedClient.getSelectedCiphersuite().isCBC()) {
                    simulatedClient.setPaddingOracleVulnerable(true);
                    simulatedClient.setConnectionSecure(false);
                } else {
                    simulatedClient.setPaddingOracleVulnerable(false);
                }
                if (report.getBleichenbacherVulnerable() && simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")) {
                    simulatedClient.setBleichenbacherVulnerable(true);
                    simulatedClient.setConnectionSecure(false);
                } else {
                    simulatedClient.setBleichenbacherVulnerable(false);
                }
                if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
                    simulatedClient.setCrimeVulnerable(true);
                    simulatedClient.setConnectionSecure(false);
                } else {
                    simulatedClient.setCrimeVulnerable(false);
                }
                if (report.getInvalidCurveVulnerable() && simulatedClient.getSelectedCiphersuite().name().contains("TLS_ECDH")) {
                    simulatedClient.setInvalidCurveVulnerable(true);
                    simulatedClient.setConnectionSecure(false);
                } else {
                    simulatedClient.setInvalidCurveVulnerable(false);
                }
                if (report.getInvalidCurveEphermaralVulnerable() && simulatedClient.getSelectedCiphersuite().name().contains("TLS_ECDHE")) {
                    simulatedClient.setInvalidCurveEphemeralVulnerable(true);
                    simulatedClient.setConnectionSecure(false);
                } else {
                    simulatedClient.setInvalidCurveEphemeralVulnerable(false);
                }
                if (report.getSweet32Vulnerable()) {
                    if (simulatedClient.getSelectedCiphersuite().name().contains("3DES") || 
                            simulatedClient.getSelectedCiphersuite().name().contains("IDEA") || 
                            simulatedClient.getSelectedCiphersuite().name().contains("GOST")) {
                        simulatedClient.setSweet32Vulnerable(true);
                        simulatedClient.setConnectionSecure(false);
                    } else {
                        simulatedClient.setSweet32Vulnerable(false);
                    }
                }
                if (report.getDrownVulnerable().equals(DrownVulnerabilityType.SSL2) && simulatedClient.getSelectedProtocolVersion().equals(ProtocolVersion.SSL2)) {
                    simulatedClient.setDrownVulnerable(true);
                } else {
                    simulatedClient.setDrownVulnerable(false);
                }
                if (simulatedClient.getConnectionSecure()) {
                    secureConnectionCounter++;
                }
            }
        }
        report.setConnectionSecureCounter(secureConnectionCounter);
        report.setConnectionInsecureCounter(report.getHandshakeSuccessfulCounter()-secureConnectionCounter);
    }
    
}
