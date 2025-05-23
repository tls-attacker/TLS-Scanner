/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ExtensionRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

public class RawPublicKeyProbe extends TlsServerProbe {

    private TestResult supportsRawPublicKeys = TestResults.FALSE;

    public RawPublicKeyProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RAW_PUBLIC_KEYS, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_RAW_PUBLIC_KEY_CERTIFICATES);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAddServerCertificateTypeExtension(true);
        tlsConfig.setServerCertificateTypeDesiredTypes(List.of(CertificateType.RAW_PUBLIC_KEY));
        State state = new State(tlsConfig);
        executeState(state);
        ServerHelloMessage serverHelloMessage =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        if (serverHelloMessage != null
                && state.getTlsContext()
                        .getNegotiatedExtensionSet()
                        .contains(ExtensionType.SERVER_CERTIFICATE_TYPE)
                && state.getTlsContext()
                        .getServerCertificateTypeDesiredTypes()
                        .contains(CertificateType.RAW_PUBLIC_KEY)) {
            supportsRawPublicKeys = TestResults.TRUE;
        } else {
            supportsRawPublicKeys = TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.EXTENSIONS)
                .and(new ExtensionRequirement<>(ExtensionType.SERVER_CERTIFICATE_TYPE));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_RAW_PUBLIC_KEY_CERTIFICATES, supportsRawPublicKeys);
    }
}
