/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ProtocolVersionProbe extends TlsServerProbe {

    private List<ProtocolVersion> toTestList;
    private List<ProtocolVersion> supportedProtocolVersions;
    private List<ProtocolVersion> unsupportedProtocolVersions;

    public ProtocolVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PROTOCOL_VERSION, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_DTLS_1_0_DRAFT,
                TlsAnalyzedProperty.SUPPORTS_DTLS_1_0,
                TlsAnalyzedProperty.SUPPORTS_DTLS_1_2,
                TlsAnalyzedProperty.SUPPORTS_SSL_2,
                TlsAnalyzedProperty.SUPPORTS_SSL_3,
                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS);
    }

    @Override
    protected void executeTest() {
        supportedProtocolVersions = new LinkedList<>();
        unsupportedProtocolVersions = new LinkedList<>();
        if (configSelector.foundWorkingTls13Config()) {
            // the ConfigSelector is currently better at determining 1.3 support
            supportedProtocolVersions.add(ProtocolVersion.TLS13);
        } else {
            unsupportedProtocolVersions.add(ProtocolVersion.TLS13);
        }

        for (ProtocolVersion version : toTestList) {
            if (isProtocolVersionSupported(version, false)) {
                supportedProtocolVersions.add(version);
            } else {
                unsupportedProtocolVersions.add(version);
            }
        }
        if (supportedProtocolVersions.isEmpty()) {
            for (ProtocolVersion version : unsupportedProtocolVersions) {
                if (isProtocolVersionSupported(version, true)) {
                    unsupportedProtocolVersions.remove(version);
                    supportedProtocolVersions.add(version);
                }
            }
        }
    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest, boolean intolerance) {
        if (toTest == ProtocolVersion.SSL2) {
            return isSSL2Supported();
        }
        Config tlsConfig;
        List<CipherSuite> cipherSuites = new LinkedList<>();
        tlsConfig = configSelector.getBaseConfig();
        if (intolerance) {
            cipherSuites.addAll(CipherSuite.getImplemented());
        } else {
            cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
            cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
            cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        }
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);

        if (toTest == ProtocolVersion.DTLS10_DRAFT) {
            Record record = WorkflowTraceResultUtil.getLastReceivedRecord(state.getWorkflowTrace());
            if (record != null) {
                ProtocolVersion version =
                        ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
                if (version != null) {
                    return version == ProtocolVersion.DTLS10_DRAFT;
                }
            }
            return false;
        } else {
            if (!WorkflowTraceResultUtil.didReceiveMessage(
                    state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
                LOGGER.debug("Did not receive ServerHello Message");
                LOGGER.debug(state.getWorkflowTrace().toString());
                return false;
            } else {
                LOGGER.debug("Received ServerHelloMessage");
                LOGGER.debug(state.getWorkflowTrace().toString());
                LOGGER.debug(
                        "Selected Version:"
                                + state.getTlsContext().getSelectedProtocolVersion().name());
                return state.getTlsContext().getSelectedProtocolVersion() == toTest;
            }
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
    public void adjustConfig(ServerReport report) {
        toTestList = new LinkedList<>();
        if (configSelector.getScannerConfig().getDtlsDelegate().isDTLS()) {
            toTestList.add(ProtocolVersion.DTLS10_DRAFT);
            toTestList.add(ProtocolVersion.DTLS10);
            toTestList.add(ProtocolVersion.DTLS12);
        } else {
            toTestList.add(ProtocolVersion.SSL2);
            if (configSelector.foundWorkingConfig()) {
                toTestList.add(ProtocolVersion.SSL3);
                toTestList.add(ProtocolVersion.TLS10);
                toTestList.add(ProtocolVersion.TLS11);
                toTestList.add(ProtocolVersion.TLS12);
            }
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new FulfilledRequirement<>();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0_DRAFT, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.COULD_NOT_TEST);
        put(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS, supportedProtocolVersions);
        if (supportedProtocolVersions != null) {
            for (ProtocolVersion version : supportedProtocolVersions) {
                if (version == ProtocolVersion.DTLS10_DRAFT) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0_DRAFT, TestResults.TRUE);
                }
                if (version == ProtocolVersion.DTLS10) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.TRUE);
                }
                if (version == ProtocolVersion.DTLS12) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.TRUE);
                }
                if (version == ProtocolVersion.SSL2) {
                    put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.TRUE);
                }
                if (version == ProtocolVersion.SSL3) {
                    put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS10) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS11) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS12) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS13) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE);
                }
            }

            for (ProtocolVersion version : unsupportedProtocolVersions) {
                if (version == ProtocolVersion.DTLS10_DRAFT) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0_DRAFT, TestResults.FALSE);
                }
                if (version == ProtocolVersion.DTLS10) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.FALSE);
                }
                if (version == ProtocolVersion.DTLS12) {
                    put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.FALSE);
                }
                if (version == ProtocolVersion.SSL2) {
                    put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.FALSE);
                }
                if (version == ProtocolVersion.SSL3) {
                    put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS10) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS11) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS12) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS13) {
                    put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.FALSE);
                }
            }
        }
    }
}
