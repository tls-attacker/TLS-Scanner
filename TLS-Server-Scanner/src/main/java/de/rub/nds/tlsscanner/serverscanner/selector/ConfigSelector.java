/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.IPAddress;

public class ConfigSelector {

    private ServerScannerConfig scannerConfig;
    private Config workingConfig;

    public static final String PATH = "/configs/";
    public static final String SSL2_CONFIG = "ssl2Only.config";
    public static final String TLS13_CONFIG = "tls13Only.config";
    public static final List<String> CONFIGS = Arrays.asList("default.config", "nice.config");

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean speaksProtocol = false;
    private boolean isHandshaking = false;

    public ConfigSelector(ServerScannerConfig scannerConfig) {
        this.scannerConfig = scannerConfig;
    }

    public boolean findWorkingConfig() {
        for (String resource : CONFIGS) {
            Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + resource));
            applyDelegates(config);
            applyPerformanceParamters(config);
            applyScannerConfigParameters(config);
            repairSni(config);
            repairConfig(config);
            if (configWorks(config)) {
                workingConfig = config.createCopy();
                isHandshaking = true;
                return true;
            }
        }
        return false;
    }

    private boolean configWorks(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        State state = new State(config, trace);
        WorkflowExecutor executor =
            WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig().getWorkflowExecutorType(), state);
        executor.executeWorkflow();

        List<AbstractRecord> reveicedRecords = state.getWorkflowTrace().getFirstReceivingAction().getReceivedRecords();
        if ((reveicedRecords != null && !reveicedRecords.isEmpty() && reveicedRecords.get(0) instanceof Record)
            || WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.HELLO_VERIFY_REQUEST, trace)
            || WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)
            || WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace)) {
            speaksProtocol = true;
        }
        return trace.executedAsPlanned();
    }

    private void applyPerformanceParamters(Config config) {
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setStopReceivingAfterWarning(false);
        config.setStopActionsAfterWarning(false);
        config.setEnforceSettings(false);
    }

    private void applyDelegates(Config config) throws ConfigurationException {
        for (Delegate delegate : scannerConfig.getDelegateList()) {
            delegate.applyDelegate(config);
        }
    }

    private void applyScannerConfigParameters(Config config) {
        if (scannerConfig.getCustomCAPathList() != null) {
            TrustAnchorManager.getInstance().addCustomCA(scannerConfig.getCustomCAPathList());
        }

        int timeout = scannerConfig.getTimeout();
        config.getDefaultClientConnection().setTimeout(timeout);
        if (timeout > AliasedConnection.DEFAULT_FIRST_TIMEOUT) {
            config.getDefaultClientConnection().setFirstTimeout(timeout);
        }
    }

    private void repairSni(Config config) {
        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname())
            || scannerConfig.getClientDelegate().getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }
    }

    public Config repairConfig(Config config) {
        if (config.getHighestProtocolVersion().isTLS13()) {
            config.setAddEllipticCurveExtension(true);
            config.setAddECPointFormatExtension(false);
            List<NamedGroup> tls13groups =
                config.getDefaultClientNamedGroups().stream().filter(NamedGroup::isTls13).collect(Collectors.toList());
            config.setDefaultClientNamedGroups(tls13groups);
            config.setDefaultClientKeyShareNamedGroups(config.getDefaultClientKeyShareNamedGroups().stream()
                .filter(tls13groups::contains).collect(Collectors.toList()));
        } else {
            boolean containsEc = config.getDefaultClientSupportedCipherSuites().stream()
                .filter(CipherSuite::isRealCipherSuite).filter(Predicate.not(CipherSuite::isTLS13))
                .anyMatch(cipherSuite -> AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isEC());
            config.setAddEllipticCurveExtension(containsEc);
            config.setAddECPointFormatExtension(containsEc);
        }
        CipherSuite defaultSelectedCipherSuite = config.getDefaultClientSupportedCipherSuites().stream()
            .filter(CipherSuite::isRealCipherSuite).findFirst().orElse(config.getDefaultSelectedCipherSuite());
        config.setDefaultSelectedCipherSuite(defaultSelectedCipherSuite);
        return config;
    }

    public Config getBaseConfig() {
        return workingConfig.createCopy();
    }

    public Config getSSL2BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + SSL2_CONFIG));
        applyDelegates(config);
        applyPerformanceParamters(config);
        applyScannerConfigParameters(config);
        repairSni(config);
        repairConfig(config);
        return config;
    }

    public Config getTls13BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + TLS13_CONFIG));
        applyDelegates(config);
        applyPerformanceParamters(config);
        applyScannerConfigParameters(config);
        repairSni(config);
        repairConfig(config);
        return config;
    }

    public boolean isIsHandshaking() {
        return isHandshaking;
    }

    public boolean isSpeaksProtocol() {
        return speaksProtocol;
    }

    public ServerScannerConfig getScannerConfig() {
        return scannerConfig;
    }
}
