/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailed;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeInsecure;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.CiphersuiteRater;
import de.rub.nds.tlsscanner.report.SiteReport;

public class HandshakeSimulationAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        int handshakeSuccessfulCounter = 0;
        int insecureCounter = 0;
        int secureRfc7918Counter = 0;
        if (report.getSimulatedClientList() != null) {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.getReceivedServerHello()) {
                    checkHighestPossibleProtocolVersionSeleceted(report, simulatedClient);
                }
                if (simulatedClient.getReceivedServerHelloDone()) {
                    checkIfHandshakeIsReallySuccessful(simulatedClient);
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
                    checkWhyServerHelloDoneIsMissing(report, simulatedClient);
                }
                if (simulatedClient.getHandshakeSuccessful()) {
                    handshakeSuccessfulCounter++;
                    checkIfConnectionIsInsecure(report, simulatedClient);
                    if (simulatedClient.getConnectionInsecure()) {
                        insecureCounter++;
                    } else {
                        checkIfConnectionIsRfc7918Secure(simulatedClient);
                        if (simulatedClient.getConnectionRfc7918Secure()) {
                            secureRfc7918Counter++;
                        }
                    }
                }
            }
            report.setHandshakeSuccessfulCounter(handshakeSuccessfulCounter);
            report.setHandshakeFailedCounter(report.getSimulatedClientList().size() - handshakeSuccessfulCounter);
            report.setConnectionInsecureCounter(insecureCounter);
            report.setConnectionRfc7918SecureCounter(secureRfc7918Counter);
        }
    }

    private void checkHighestPossibleProtocolVersionSeleceted(SiteReport report, SimulatedClient simulatedClient) {
        if (report.getVersions() != null) {
            if (simulatedClient.getSelectedProtocolVersion().equals(simulatedClient.getHighestClientProtocolVersion())) {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
            } else {
                boolean serverSupportsClientVersion = false;
                for (ProtocolVersion version : report.getVersions()) {
                    if (version.equals(simulatedClient.getHighestClientProtocolVersion())) {
                        serverSupportsClientVersion = true;
                    }
                }
                if (!serverSupportsClientVersion) {
                    simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                } else {
                    simulatedClient.setHighestPossibleProtocolVersionSeleceted(false);
                }
            }
        }
    }

    private void checkIfHandshakeIsReallySuccessful(SimulatedClient simulatedClient) {
        boolean reallySuccessful = true;
        if (isCiphersuiteForbidden(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_FORBIDDEN);
            reallySuccessful = false;
        }
        if (isPublicKeyLengthNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_LENGTH_NOT_ACCEPTED);
            reallySuccessful = false;
        }
        simulatedClient.setHandshakeSuccessful(reallySuccessful);
    }

    private boolean isCiphersuiteForbidden(SimulatedClient simulatedClient) {
        if (simulatedClient.getSelectedCiphersuite().isSupportedInProtocol(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        } else if (simulatedClient.getVersionAcceptForbiddenCiphersuiteList() != null
                && simulatedClient.getVersionAcceptForbiddenCiphersuiteList().contains(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        }
        return true;
    }

    private boolean isPublicKeyLengthNotAccepted(SimulatedClient simulatedClient) {
        if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")
                && simulatedClient.getSupportedRsaKeyLengthList() != null
                && simulatedClient.getSupportedRsaKeyLengthList().contains(Integer.parseInt(simulatedClient.getServerPublicKeyLength()))) {
            return false;
        }
        if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_DHE_RSA")
                && simulatedClient.getSupportedDheKeyLengthList() != null
                && simulatedClient.getSupportedDheKeyLengthList().contains(Integer.parseInt(simulatedClient.getServerPublicKeyLength()))) {
            return false;
        }
        return true;
    }

    private void checkWhyServerHelloDoneIsMissing(SiteReport report, SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isProtocolMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH);
            reasonFound = true;
        }
        if (isCiphersuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_MISMATCH);
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN);
        }
    }

    private boolean isProtocolMismatch(SiteReport report, SimulatedClient simulatedClient) {
        for (ProtocolVersion serverVersion : report.getVersions()) {
            for (ProtocolVersion clientVersion : simulatedClient.getSupportedVersionList()) {
                if (serverVersion.equals(clientVersion)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isCiphersuiteMismatch(SiteReport report, SimulatedClient simulatedClient) {
        for (CipherSuite serverCipherSuite : report.getCipherSuites()) {
            for (CipherSuite clientCipherSuite : simulatedClient.getClientSupportedCiphersuites()) {
                if (serverCipherSuite.equals(clientCipherSuite)) {
                    return false;
                }
            }
        }
        return true;
    }

    private void checkIfConnectionIsInsecure(SiteReport report, SimulatedClient simulatedClient) {
        boolean connectionInsecure = false;
        if (isCipherSuiteGradeLow(simulatedClient)) {
            simulatedClient.addToInsecureReasons(HandshakeInsecure.CIPHERSUITE_GRADE_LOW);
            connectionInsecure = true;
        }
        if (isVulnerable(report, simulatedClient)) {
            connectionInsecure = true;
        }
        simulatedClient.setConnectionInsecure(connectionInsecure);
    }

    private boolean isCipherSuiteGradeLow(SimulatedClient simulatedClient) {
        return CiphersuiteRater.getGrade(simulatedClient.getSelectedCiphersuite()).equals(CipherSuiteGrade.LOW);
    }

    private boolean isVulnerable(SiteReport report, SimulatedClient simulatedClient) {
        boolean isVulnerable = false;
        if (report.getPaddingOracleVulnerable() != null && report.getPaddingOracleVulnerable()
                && simulatedClient.getSelectedCiphersuite().isCBC()) {
            simulatedClient.addToInsecureReasons(HandshakeInsecure.PADDING_ORACLE);
            isVulnerable = true;
        }
        if (report.getBleichenbacherVulnerable() != null && report.getBleichenbacherVulnerable()
                && simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")) {
            simulatedClient.addToInsecureReasons(HandshakeInsecure.BLEICHENBACHER);
            isVulnerable = true;
        }
        if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
            simulatedClient.addToInsecureReasons(HandshakeInsecure.CRIME);
            isVulnerable = true;
        }
        if (report.getSweet32Vulnerable() != null && report.getSweet32Vulnerable()) {
            if (simulatedClient.getSelectedCiphersuite().name().contains("3DES")
                    || simulatedClient.getSelectedCiphersuite().name().contains("IDEA")
                    || simulatedClient.getSelectedCiphersuite().name().contains("GOST")) {
                simulatedClient.addToInsecureReasons(HandshakeInsecure.SWEET32);
                isVulnerable = true;
            }
        }
        return isVulnerable;
    }

    private void checkIfConnectionIsRfc7918Secure(SimulatedClient simulatedClient) {
        simulatedClient.setConnectionRfc7918Secure(false);
    }
}
