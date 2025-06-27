/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpProbe extends TlsServerProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    // SRP cipher suites from RFC 5054
    private static final List<CipherSuite> SRP_CIPHER_SUITES =
            Arrays.asList(
                    CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA);

    // Test SRP identity
    private static final byte[] TEST_SRP_IDENTITY = "testuser".getBytes();

    private Boolean supportsSrpExtension = null;
    private Boolean missingSrpExtensionBug = null;
    private List<CipherSuite> supportedSrpCipherSuites = null;

    public SrpProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SRP, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_SRP_EXTENSION,
                TlsAnalyzedProperty.SRP_CIPHERSUITES,
                TlsAnalyzedProperty.MISSING_SRP_EXTENSION_BUG);
    }

    @Override
    public void executeTest() {
        // Test basic SRP support with extension
        testSrpWithExtension();

        // Test for missing SRP extension bug
        testMissingSrpExtensionBug();
    }

    private void testSrpWithExtension() {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDefaultClientSupportedCipherSuites(SRP_CIPHER_SUITES);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setEnforceSettings(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setAddServerNameIndicationExtension(true);

        // Add SRP extension
        SRPExtensionMessage srpExtension = new SRPExtensionMessage();
        srpExtension.setSrpIdentifier(Modifiable.explicit(TEST_SRP_IDENTITY));
        srpExtension.setSrpIdentifierLength(Modifiable.explicit(TEST_SRP_IDENTITY.length));

        config.setAddSRPExtension(true);
        config.setSecureRemotePasswordExtensionIdentifier(TEST_SRP_IDENTITY);

        State state = new State(config);
        executeState(state);

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);

        if (serverHello != null && serverHello.getSelectedCipherSuite() != null) {
            CipherSuite selectedSuite =
                    CipherSuite.getCipherSuite(serverHello.getSelectedCipherSuite().getValue());
            if (SRP_CIPHER_SUITES.contains(selectedSuite)) {
                supportsSrpExtension = true;
                supportedSrpCipherSuites = new ArrayList<>();
                supportedSrpCipherSuites.add(selectedSuite);

                // Test other SRP cipher suites
                for (CipherSuite suite : SRP_CIPHER_SUITES) {
                    if (!suite.equals(selectedSuite) && testSingleSrpCipherSuite(suite)) {
                        supportedSrpCipherSuites.add(suite);
                    }
                }
            } else {
                supportsSrpExtension = false;
                supportedSrpCipherSuites = new ArrayList<>();
            }
        } else {
            supportsSrpExtension = false;
            supportedSrpCipherSuites = new ArrayList<>();
        }
    }

    private boolean testSingleSrpCipherSuite(CipherSuite cipherSuite) {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDefaultClientSupportedCipherSuites(Arrays.asList(cipherSuite));
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setEnforceSettings(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setAddSRPExtension(true);
        config.setSecureRemotePasswordExtensionIdentifier(TEST_SRP_IDENTITY);

        State state = new State(config);
        executeState(state);

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);

        if (serverHello != null && serverHello.getSelectedCipherSuite() != null) {
            CipherSuite selectedSuite =
                    CipherSuite.getCipherSuite(serverHello.getSelectedCipherSuite().getValue());
            return selectedSuite.equals(cipherSuite);
        }
        return false;
    }

    private void testMissingSrpExtensionBug() {
        // Test if server properly rejects SRP cipher suites without SRP extension
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDefaultClientSupportedCipherSuites(SRP_CIPHER_SUITES);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setEnforceSettings(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setAddSRPExtension(false); // Explicitly don't add SRP extension

        State state = new State(config);
        executeState(state);

        // Check if we received an alert
        AlertMessage alert = null;
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), ProtocolMessageType.ALERT)) {
            alert =
                    (AlertMessage)
                            WorkflowTraceResultUtil.getFirstReceivedMessage(
                                    state.getWorkflowTrace(), ProtocolMessageType.ALERT);
        }

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);

        if (serverHello != null && serverHello.getSelectedCipherSuite() != null) {
            CipherSuite selectedSuite =
                    CipherSuite.getCipherSuite(serverHello.getSelectedCipherSuite().getValue());
            if (SRP_CIPHER_SUITES.contains(selectedSuite)) {
                // Server selected SRP cipher suite without SRP extension - this is a bug
                missingSrpExtensionBug = true;
            } else {
                missingSrpExtensionBug = false;
            }
        } else if (alert != null && alert.getLevel() != null && alert.getDescription() != null) {
            // Check if we got the expected alert
            if (alert.getLevel().getValue() == AlertLevel.FATAL.getValue()
                    && alert.getDescription().getValue()
                            == AlertDescription.UNKNOWN_PSK_IDENTITY.getValue()) {
                // Correct behavior - server sent unknown_psk_identity alert
                missingSrpExtensionBug = false;
            } else {
                // Server sent an alert but not the expected one
                missingSrpExtensionBug = false;
            }
        } else {
            // No clear response
            missingSrpExtensionBug = false;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<ServerReport>(ProtocolType.TLS)
                .and(new WorkingConfigRequirement(configSelector));
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        if (supportsSrpExtension != null) {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SRP_EXTENSION, supportsSrpExtension);
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SRP_EXTENSION, false);
        }

        if (supportedSrpCipherSuites != null && !supportedSrpCipherSuites.isEmpty()) {
            report.putResult(TlsAnalyzedProperty.SRP_CIPHERSUITES, supportedSrpCipherSuites);
        } else {
            report.putResult(TlsAnalyzedProperty.SRP_CIPHERSUITES, new ArrayList<CipherSuite>());
        }

        if (missingSrpExtensionBug != null) {
            report.putResult(TlsAnalyzedProperty.MISSING_SRP_EXTENSION_BUG, missingSrpExtensionBug);
        } else {
            report.putResult(TlsAnalyzedProperty.MISSING_SRP_EXTENSION_BUG, false);
        }
    }
}
