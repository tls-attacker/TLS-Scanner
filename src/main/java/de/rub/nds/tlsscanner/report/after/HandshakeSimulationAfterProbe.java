/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;

public class HandshakeSimulationAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        int secureConnectionCounter = 0;
        if (report.getSimulatedClientList() != null) {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.getReceivedServerHello()) {
                    if (report.getVersions() != null) {
                        if (simulatedClient.getSelectedProtocolVersion().equals(simulatedClient.getHighestClientProtocolVersion())) {
                            simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                        } else {
                            boolean serverProvidesClientVersion = false;
                            for (ProtocolVersion version : report.getVersions()) {
                                if (version.equals(simulatedClient.getHighestClientProtocolVersion())) {
                                    serverProvidesClientVersion = true;
                                }
                            }
                            if (!serverProvidesClientVersion) {
                                simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                            } else {
                                simulatedClient.setHighestPossibleProtocolVersionSeleceted(false);
                            }
                        }
                    }
                }
                if (simulatedClient.getHandshakeSuccessful()) {
                    simulatedClient.setConnectionSecure(true);
                    List<String> vulnerabilities = new LinkedList<>();
                    if (report.getPaddingOracleVulnerable() != null) {
                        if (report.getPaddingOracleVulnerable() 
                                && simulatedClient.getSelectedCiphersuite().isCBC()) {
                            simulatedClient.setPaddingOracleVulnerable(true);
                            simulatedClient.setConnectionSecure(false);
                            vulnerabilities.add("PaddingOracle");
                        } else {
                            simulatedClient.setPaddingOracleVulnerable(false);
                        }
                    }
                    if (report.getBleichenbacherVulnerable() != null) {
                        if (report.getBleichenbacherVulnerable() 
                                && simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")) {
                            simulatedClient.setBleichenbacherVulnerable(true);
                            simulatedClient.setConnectionSecure(false);
                            vulnerabilities.add("Bleichenbacher");
                        } else {
                            simulatedClient.setBleichenbacherVulnerable(false);
                        }
                    }
                    if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
                        simulatedClient.setCrimeVulnerable(true);
                        simulatedClient.setConnectionSecure(false);
                        vulnerabilities.add("Crime");
                    } else {
                        simulatedClient.setCrimeVulnerable(false);
                    }
                    if (report.getSweet32Vulnerable() != null) {
                        if (report.getSweet32Vulnerable()) {
                            if (simulatedClient.getSelectedCiphersuite().name().contains("3DES")
                                    || simulatedClient.getSelectedCiphersuite().name().contains("IDEA")
                                    || simulatedClient.getSelectedCiphersuite().name().contains("GOST")) {
                                simulatedClient.setSweet32Vulnerable(true);
                                simulatedClient.setConnectionSecure(false);
                                vulnerabilities.add("Sweet32");
                            } else {
                                simulatedClient.setSweet32Vulnerable(false);
                            }
                        }
                    }
                    if (!vulnerabilities.isEmpty()) {
                        simulatedClient.setConnectionInsecureBecause("Vulnerabilities: " + vulnerabilities);
                    }
                    if (simulatedClient.getConnectionSecure()) {
                        secureConnectionCounter++;
                    }
                }
            }
            report.setConnectionSecureCounter(secureConnectionCounter);
            report.setConnectionInsecureCounter(report.getHandshakeSuccessfulCounter() - secureConnectionCounter);
        }
    }

}
