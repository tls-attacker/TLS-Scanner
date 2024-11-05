/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.execution.Scanner;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.clientscanner.afterprobe.AlpacaAfterProbe;
import de.rub.nds.tlsscanner.clientscanner.afterprobe.ClientRandomnessAfterProbe;
import de.rub.nds.tlsscanner.clientscanner.afterprobe.DhValueAfterProbe;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.AlpnProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ApplicationMessageProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.BasicProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CcaSupportProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ConnectionClosingProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DheParameterProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsBugsProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsFragmentationProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsHelloVerifyRequestProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsMessageSequenceProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsReorderingProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DtlsRetransmissionsProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ECPointFormatProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.NamedGroupsProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.RecordFragmentationProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ServerCertificateKeySizeProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.TlsClientProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Version13RandomProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.afterprobe.DtlsRetransmissionAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.FreakAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.LogjamAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.core.config.delegate.CallbackDelegate;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.CbcIvExtractor;
import de.rub.nds.tlsscanner.core.passive.DhPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.DtlsRetransmissionsExtractor;
import de.rub.nds.tlsscanner.core.passive.EcPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.RandomExtractor;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsClientScanner
        extends Scanner<ClientReport, TlsClientProbe, AfterProbe<ClientReport>, State> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ClientScannerConfig config;
    private boolean closeAfterFinishParallel;

    public TlsClientScanner(ClientScannerConfig config) {
        super(config.getExecutorConfig());
        this.config = config;
        parallelExecutor =
                ParallelExecutor.create(config.getExecutorConfig().getOverallThreads(), 3);
        closeAfterFinishParallel = true;
        setCallbacks();
    }

    public TlsClientScanner(ClientScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getExecutorConfig());
        this.config = config;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        setCallbacks();
    }

    /**
     * Sets the appropriate executor callbacks possibly provided through the callback delegate. The
     * client run command will be executed after the BeforeTransportInitCallback.
     */
    private void setCallbacks() {
        if (config.getCallbackDelegate().getBeforeTransportPreInitCallback() != null
                && parallelExecutor.getDefaultBeforeTransportPreInitCallback() == null) {
            parallelExecutor.setDefaultBeforeTransportPreInitCallback(
                    config.getCallbackDelegate().getBeforeTransportPreInitCallback());
        }

        if (parallelExecutor.getDefaultBeforeTransportInitCallback() == null) {
            parallelExecutor.setDefaultBeforeTransportInitCallback(
                    CallbackDelegate.mergeCallbacks(
                            config.getCallbackDelegate().getBeforeTransportInitCallback(),
                            config.getRunCommandExecutionCallback()));
        }

        if (config.getCallbackDelegate().getAfterTransportInitCallback() != null
                && parallelExecutor.getDefaultAfterTransportInitCallback() == null) {
            parallelExecutor.setDefaultAfterTransportInitCallback(
                    config.getCallbackDelegate().getAfterTransportInitCallback());
        }

        if (parallelExecutor.getDefaultAfterExecutionCallback() == null) {
            parallelExecutor.setDefaultAfterExecutionCallback(
                    CallbackDelegate.mergeCallbacks(
                            config.getCallbackDelegate().getAfterExecutionCallback(),
                            getKillAllSpawnedSubprocessesCallback()));
        }
    }

    @Override
    protected ClientReport getEmptyReport() {
        return new ClientReport();
    }

    @Override
    protected StatsWriter<State> getDefaultProbeWriter() {
        StatsWriter<State> statsWriter = new StatsWriter<>();
        statsWriter.addExtractor(new RandomExtractor());
        statsWriter.addExtractor(new DhPublicKeyExtractor());
        statsWriter.addExtractor(new EcPublicKeyExtractor());
        statsWriter.addExtractor(new CbcIvExtractor());
        statsWriter.addExtractor(new DtlsRetransmissionsExtractor());
        return statsWriter;
    }

    @Override
    protected void onScanStart() {
        adjustServerPort();
    }

    private void adjustServerPort() {
        if (config.getExecutorConfig().isMultithreaded()
                && config.getServerDelegate().getPort() != 0) {
            LOGGER.warn(
                    "Configured explicit server port, but also multithreaded execution. Ignoring explicit port.");
            config.getServerDelegate().setPort(0);
        }
    }

    @Override
    protected boolean checkScanPrerequisites(ClientReport report) {
        ProtocolType protocolType =
                config.getDtlsDelegate().isDTLS() ? ProtocolType.DTLS : ProtocolType.TLS;
        report.putResult(TlsAnalyzedProperty.PROTOCOL_TYPE, protocolType);
        return true;
    }

    @Override
    protected void fillProbeLists() {
        registerProbeForExecution(new BasicProbe(parallelExecutor, config));
        registerProbeForExecution(new ProtocolVersionProbe(parallelExecutor, config));
        registerProbeForExecution(new CipherSuiteProbe(parallelExecutor, config));
        registerProbeForExecution(new CompressionProbe(parallelExecutor, config));
        registerProbeForExecution(new CcaSupportProbe(parallelExecutor, config));
        registerProbeForExecution(new CertificateProbe(parallelExecutor, config));
        registerProbeForExecution(new DheParameterProbe(parallelExecutor, config));
        registerProbeForExecution(new FreakProbe(parallelExecutor, config));
        registerProbeForExecution(new ApplicationMessageProbe(parallelExecutor, config));
        registerProbeForExecution(new PaddingOracleProbe(parallelExecutor, config));
        registerProbeForExecution(new AlpnProbe(parallelExecutor, config));
        registerProbeForExecution(new SniProbe(parallelExecutor, config));
        registerProbeForExecution(new ResumptionProbe(parallelExecutor, config));
        registerProbeForExecution(new ServerCertificateKeySizeProbe(parallelExecutor, config));
        registerProbeForExecution(new ConnectionClosingProbe(parallelExecutor, config));
        registerProbeForExecution(new ECPointFormatProbe(parallelExecutor, config));
        registerProbeForExecution(new NamedGroupsProbe(parallelExecutor, config));
        registerProbeForExecution(new Sweet32AfterProbe<>());
        registerProbeForExecution(new FreakAfterProbe<>());
        registerProbeForExecution(new LogjamAfterProbe<>());
        registerProbeForExecution(new ClientRandomnessAfterProbe());
        registerProbeForExecution(new EcPublicKeyAfterProbe<>());
        registerProbeForExecution(new DhValueAfterProbe());
        registerProbeForExecution(new AlpacaAfterProbe());
        registerProbeForExecution(new PaddingOracleIdentificationAfterProbe<>());
        // DTLS-specific
        registerProbeForExecution(new DtlsReorderingProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsFragmentationProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsHelloVerifyRequestProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsBugsProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsMessageSequenceProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsRetransmissionsProbe(parallelExecutor, config));
        registerProbeForExecution(new DtlsRetransmissionAfterProbe<>());
        // TLS-specific
        registerProbeForExecution(new Version13RandomProbe(parallelExecutor, config));
        registerProbeForExecution(new RecordFragmentationProbe(parallelExecutor, config));
        registerProbeForExecution(new ResumptionProbe(parallelExecutor, config));
    }

    /**
     * Provides a callback that kills all the processes that have been spawned during this state
     * execution.
     *
     * @return A callback that kills all spawned subprocesses
     */
    private Function<State, Integer> getKillAllSpawnedSubprocessesCallback() {
        return (State state) -> {
            state.killAllSpawnedSubprocesses();
            return 0;
        };
    }

    @Override
    public void close() {
        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }
}
