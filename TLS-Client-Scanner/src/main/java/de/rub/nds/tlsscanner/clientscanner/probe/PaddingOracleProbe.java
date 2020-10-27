/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe.SupportedCipherSuitesResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.attacker.ClientParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.leak.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.info.PaddingOracleTestInfo;

public class PaddingOracleProbe extends BaseProbe {
    // #region static
    private static final ProtocolVersion[] VERSIONS_TO_TEST = {
            ProtocolVersion.TLS10,
            ProtocolVersion.TLS11,
            ProtocolVersion.TLS12
    };
    private static final PaddingVectorGeneratorType[] VECTOR_TYPES = {
            PaddingVectorGeneratorType.CLASSIC_DYNAMIC,
            PaddingVectorGeneratorType.FINISHED,
            PaddingVectorGeneratorType.CLOSE_NOTIFY,
            PaddingVectorGeneratorType.FINISHED_RESUMPTION
    };

    public static Collection<PaddingOracleProbe> getAll(IOrchestrator orchestrator) {
        Collection<PaddingOracleProbe> ret = new ArrayList<>();
        for (ProtocolVersion version : VERSIONS_TO_TEST) {
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                for (PaddingVectorGeneratorType vectorGeneratorType : VECTOR_TYPES) {
                    if (suite.isCBC()) {
                        PaddingOracleParameters params = new PaddingOracleParameters(version, suite,
                                vectorGeneratorType);
                        ret.add(new PaddingOracleProbe(orchestrator, params));
                    }
                }
            }
        }
        return ret;
    }
    // #endregion

    private final PaddingOracleParameters params;

    public PaddingOracleProbe(IOrchestrator orchestrator, PaddingOracleParameters params) {
        super(orchestrator);
        this.params = params;
    }

    // #region boilerplate

    @Override
    public String getHostnameForStandalone() {
        return null; // not a standalone probe
    }

    @Override
    protected String getHostnamePrefix() {
        return String.join(".", (CharSequence[]) new String[] {
                params.paddingVectorGeneratorType.toString(),
                params.cipherSuite.toString(),
                params.protocolVersion.toString(),
                super.getHostnamePrefix()
        });
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return ProbeRequirements.TRUE()
                .needResultOfTypeMatching(
                        SupportedCipherSuitesProbe.class,
                        SupportedCipherSuitesResult.class,
                        SupportedCipherSuitesResult::supportsBlockCiphers,
                        "Client does not support block ciphers")
                .needResultOfTypeMatching(
                        VersionProbe.class,
                        ParametrizedClientProbeResult.class,
                        res -> ((ParametrizedClientProbeResult<ProtocolVersion, Boolean>) res)
                                .get(params.protocolVersion).booleanValue(),
                        "Client does not support ProtocolVersion " + params.protocolVersion)
                .needResultOfTypeMatching(
                        SupportedCipherSuitesProbe.class,
                        SupportedCipherSuitesResult.class,
                        res -> res.supports(params.cipherSuite),
                        "Client does not support CipherSuite " + params.cipherSuite);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        // TODO do not merge all could not execute results
        // one should be sufficient
        return super.getCouldNotExecuteResult(report);
    }
    // #endregion

    // #region helper functions
    public PaddingOracleCommandConfig createPaddingOracleCommandConfig() {
        ClientScannerConfig csConfig = orchestrator.getCSConfig();
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(
                csConfig.getGeneralDelegate());
        // set any remote Address - this is just to avoid any exception
        ClientDelegate clientDelegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        clientDelegate.setHost("localhost:0");

        StarttlsDelegate startTlsDelegate = paddingOracleConfig.getDelegate(StarttlsDelegate.class);
        startTlsDelegate.setStarttlsType(csConfig.getDelegate(StarttlsDelegate.class).getStarttlsType());

        // TODO set recordGeneratorType dynamically
        PaddingRecordGeneratorType recordGeneratorType = PaddingRecordGeneratorType.SHORT;

        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
        paddingOracleConfig.setVectorGeneratorType(params.paddingVectorGeneratorType);
        paddingOracleConfig.getCiphersuiteDelegate().setCipherSuites(params.cipherSuite);
        paddingOracleConfig.getProtocolVersionDelegate().setProtocolVersion(params.protocolVersion);
        return paddingOracleConfig;
    }

    public InformationLeakTest<PaddingOracleTestInfo> getPaddingOracleInformationLeakTest(
            PaddingOracleCommandConfig paddingOracleConfig, ClientParallelExecutor executor) {
        PaddingOracleAttacker attacker = new PaddingOracleAttacker(
                paddingOracleConfig,
                orchestrator.getCSConfig().createConfig(),
                executor);
        Config config = attacker.getGeneratedConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.setAddServerNameIndicationExtension(false);
        attacker.isVulnerable();
        return new InformationLeakTest<>(
                new PaddingOracleTestInfo(
                        paddingOracleConfig.getProtocolVersionDelegate().getProtocolVersion(),
                        paddingOracleConfig.getCiphersuiteDelegate().getCipherSuites().get(0),
                        paddingOracleConfig.getVectorGeneratorType(),
                        paddingOracleConfig.getRecordGeneratorType()),
                attacker.getResponseMapList());
    }
    // #endregion

    @Override
    protected ClientProbeResult callInternal(ClientReport report, String hostnamePrefix)
            throws InterruptedException, ExecutionException {
        PaddingOracleCommandConfig paddingOracleConfig = createPaddingOracleCommandConfig();
        ClientParallelExecutor executor = new ClientParallelExecutor(orchestrator, report, report.uid, hostnamePrefix);
        InformationLeakTest<PaddingOracleTestInfo> res = getPaddingOracleInformationLeakTest(paddingOracleConfig,
                executor);
        return new ParametrizedClientProbeResult<PaddingOracleParameters, PaddingOracleResult>(
                getClass(), params,
                new PaddingOracleResult(res));
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        // handled by ConfiguredTraceDispatcher
        return null;
    }

    // #region helping classes
    public static class PaddingOracleParameters implements Serializable {
        public final ProtocolVersion protocolVersion;
        public final CipherSuite cipherSuite;
        public final PaddingVectorGeneratorType paddingVectorGeneratorType;

        public PaddingOracleParameters(ProtocolVersion protocolVersion, CipherSuite cipherSuite,
                PaddingVectorGeneratorType paddingVectorGeneratorType) {
            this.protocolVersion = protocolVersion;
            this.cipherSuite = cipherSuite;
            this.paddingVectorGeneratorType = paddingVectorGeneratorType;
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class PaddingOracleResult implements Serializable {
        public boolean vulnerable;

        public PaddingOracleResult(InformationLeakTest<PaddingOracleTestInfo> res) {
            this.vulnerable = res.isSignificantDistinctAnswers();
        }
    }
    // #endregion

}
