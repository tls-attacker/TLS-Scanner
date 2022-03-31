/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TlsPoodleResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class TlsPoodleProbe extends TlsProbe {

    private List<VersionSuiteListPair> serverSupportedSuites;

    private TestResult vulnerable = TestResult.FALSE;

    public TlsPoodleProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TLS_POODLE, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        LOGGER.debug("Starting evaluation");
        for (VersionSuiteListPair pair : serverSupportedSuites) {
            if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                List<CipherSuite> suites = new ArrayList<>();
                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    if (!suite.isPsk() && suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                        suites.add(suite);
                    }
                }
                if (isVulnerable(getConfig(pair.getVersion(), suites)) == TestResult.TRUE) {
                    vulnerable = TestResult.TRUE;
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        return new TlsPoodleResult(vulnerable);
    }

    private Config getConfig(ProtocolVersion version, List<CipherSuite> suites) {
        Config tlsConfig = getConfigSelector().getBaseConfig();
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.setDefaultClientSupportedCipherSuites(suites);
        tlsConfig.setStopReceivingAfterFatal(false);
        tlsConfig.setStopActionsAfterFatal(false);
        tlsConfig.setStopActionsAfterIOException(false);
        tlsConfig.setStopTraceAfterUnexpected(false);
        tlsConfig.setStopReceivingAfterWarning(false);
        tlsConfig.setStopActionsAfterWarning(false);
        getConfigSelector().repairConfig(tlsConfig);
        return tlsConfig;
    }

    private TestResult isVulnerable(Config config) {
        State state = new State(config, getTrace(config));
        executeState(state);
        if (state.getTlsContext().isReceivedFatalAlert()) {
            LOGGER.debug(
                "NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
            return TestResult.FALSE;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            LOGGER.debug("Vulnerable (definitely), Finished message found");
            return TestResult.TRUE;
        } else {
            LOGGER.debug("Not vulnerable (probably), no Finished message found, yet also no alert");
            return TestResult.FALSE;
        }
    }

    private WorkflowTrace getTrace(Config tlsConfig) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<AbstractRecord> recordList = new LinkedList<>();
        for (ProtocolMessage msg : sendAction.getMessages()) {
            if (msg instanceof FinishedMessage) {
                recordList.add(getFinishedMessageRecord());
            } else {
                recordList.add(new Record());
            }
        }
        sendAction.setRecords(recordList);
        return trace;
    }

    private Record getFinishedMessageRecord() {
        // https://mta.openssl.org/pipermail/openssl-announce/2018-March/000119.html
        // Some implementations only test the least significant bit of each
        // byte.
        // https://yngve.vivaldi.net/2015/07/14/there-are-more-poodles-in-the-forest/
        // 4800 servers test the last byte of the padding, but not the first.
        // 240 servers (which is much lower) check the first byte, but not the
        // last byte.
        // Therefore, we flip just the most significant bit of the first byte in
        // the padding.
        ModifiableByteArray padding = new ModifiableByteArray();
        padding.setModification(ByteArrayModificationFactory.xor(new byte[] { (byte) 0x80 }, 0));
        Record finishedMessageRecord = new Record();
        finishedMessageRecord.prepareComputations();
        finishedMessageRecord.getComputations().setPadding(padding);
        return finishedMessageRecord;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new TlsPoodleResult(TestResult.COULD_NOT_TEST);
    }
}
