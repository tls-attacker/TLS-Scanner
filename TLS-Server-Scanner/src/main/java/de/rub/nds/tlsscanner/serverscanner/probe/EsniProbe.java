/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.EsniResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SniResult;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class EsniProbe extends TlsProbe {

    public EsniProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.ESNI, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(this.getClientSupportedCipherSuites());
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);

        tlsConfig.setDefaultClientNamedGroups(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        List<NamedGroup> keyShareGroupList = new LinkedList<>();
        keyShareGroupList.add(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultClientKeyShareNamedGroups(keyShareGroupList);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setClientSupportedEsniCipherSuites(this.getClientSupportedCipherSuites());
        tlsConfig.getClientSupportedEsniNamedGroups().addAll(this.getImplementedGroups());
        tlsConfig.setAddServerNameIndicationExtension(false);
        tlsConfig.setAddEncryptedServerNameIndicationExtension(true);

        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
            RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        executeState(state);

        TlsContext context = state.getTlsContext();
        boolean isDnsKeyRecordAvailable = context.getEsniRecordBytes() != null;
        boolean isReceivedCorrectNonce = context.getEsniServerNonce() != null
            && Arrays.equals(context.getEsniServerNonce(), context.getEsniClientNonce());
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return new SniResult(TestResult.ERROR_DURING_TEST);
        } else if (isDnsKeyRecordAvailable && isReceivedCorrectNonce) {
            return (new EsniResult(TestResult.TRUE));
        } else {
            return (new EsniResult(TestResult.FALSE));
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SniResult(TestResult.COULD_NOT_TEST);
    }

    private List<CipherSuite> getClientSupportedCipherSuites() {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        return cipherSuites;
    }

    private List<NamedGroup> getImplementedGroups() {
        List<NamedGroup> list = new LinkedList();
        list.add(NamedGroup.ECDH_X25519);
        list.add(NamedGroup.ECDH_X448);
        list.add(NamedGroup.SECP160K1);
        list.add(NamedGroup.SECP160R1);
        list.add(NamedGroup.SECP160R2);
        list.add(NamedGroup.SECP192K1);
        list.add(NamedGroup.SECP192R1);
        list.add(NamedGroup.SECP224K1);
        list.add(NamedGroup.SECP224R1);
        list.add(NamedGroup.SECP256K1);
        list.add(NamedGroup.SECP256R1);
        list.add(NamedGroup.SECP384R1);
        list.add(NamedGroup.SECP521R1);
        list.add(NamedGroup.SECT163K1);
        list.add(NamedGroup.SECT163R1);
        list.add(NamedGroup.SECT163R2);
        list.add(NamedGroup.SECT193R1);
        list.add(NamedGroup.SECT193R2);
        list.add(NamedGroup.SECT233K1);
        list.add(NamedGroup.SECT233R1);
        list.add(NamedGroup.SECT239K1);
        list.add(NamedGroup.SECT283K1);
        list.add(NamedGroup.SECT283R1);
        list.add(NamedGroup.SECT409K1);
        list.add(NamedGroup.SECT409R1);
        list.add(NamedGroup.SECT571K1);
        list.add(NamedGroup.SECT571R1);
        return list;
    }

}
