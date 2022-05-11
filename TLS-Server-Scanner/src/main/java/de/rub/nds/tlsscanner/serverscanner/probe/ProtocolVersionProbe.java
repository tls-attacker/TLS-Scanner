/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ProtocolVersionResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ProtocolVersionProbe extends TlsServerProbe<ConfigSelector, ServerReport, ProtocolVersionResult> {

    private List<ProtocolVersion> toTestList;

    public ProtocolVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PROTOCOL_VERSION, configSelector);
        toTestList = new LinkedList<>();
        if (configSelector.getScannerConfig().getDtlsDelegate().isDTLS()) {
            toTestList.add(ProtocolVersion.DTLS10);
            toTestList.add(ProtocolVersion.DTLS12);
        } else {
            toTestList.add(ProtocolVersion.SSL2);
            toTestList.add(ProtocolVersion.SSL3);
            toTestList.add(ProtocolVersion.TLS10);
            toTestList.add(ProtocolVersion.TLS11);
            toTestList.add(ProtocolVersion.TLS12);
            toTestList.add(ProtocolVersion.TLS13);
        }
    }

    @Override
    public ProtocolVersionResult executeTest() {
        List<ProtocolVersion> supportedVersionList = new LinkedList<>();
        List<ProtocolVersion> unsupportedVersionList = new LinkedList<>();
        for (ProtocolVersion version : toTestList) {
            if (isProtocolVersionSupported(version, false)) {
                supportedVersionList.add(version);
            } else {
                unsupportedVersionList.add(version);
            }
        }
        if (supportedVersionList.isEmpty()) {
            unsupportedVersionList = new LinkedList<>();
            for (ProtocolVersion version : toTestList) {
                if (isProtocolVersionSupported(version, true)) {
                    supportedVersionList.add(version);
                } else {
                    unsupportedVersionList.add(version);
                }
            }
        }
        return new ProtocolVersionResult(supportedVersionList, unsupportedVersionList);
    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest, boolean intolerance) {
        if (toTest == ProtocolVersion.SSL2) {
            return isSSL2Supported();
        }
        Config tlsConfig;
        List<CipherSuite> cipherSuites = new LinkedList<>();
        if (!toTest.isTLS13()) {
            tlsConfig = configSelector.getBaseConfig();
            if (intolerance) {
                cipherSuites.addAll(CipherSuite.getImplemented());
            } else {
                cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
                cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
                cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }
        } else {
            tlsConfig = configSelector.getTls13BaseConfig();
            cipherSuites.addAll(CipherSuite.getTls13CipherSuites());
        }
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == toTest;
        }
    }

    private boolean isSSL2Supported() {
        Config tlsConfig = configSelector.getSSL2BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SSL2_HELLO);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned();
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public ProtocolVersionResult getCouldNotExecuteResult() {
        return new ProtocolVersionResult(null, null);
    }

}
