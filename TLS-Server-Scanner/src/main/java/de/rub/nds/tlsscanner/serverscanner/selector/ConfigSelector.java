/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.IPAddress;

public class ConfigSelector {

    public String getConfigProfileIdentifier() {
        return configProfileIdentifier;
    }

    public String getConfigProfileIdentifierTls13() {
        return configProfileIdentifierTls13;
    }

    private final ServerScannerConfig scannerConfig;
    private final ParallelExecutor parallelExecutor;
    private Config workingConfig;
    private String configProfileIdentifier;
    private Config workingTl13Config;
    private String configProfileIdentifierTls13;

    public static final String PATH = "/configs/";
    public static final String SSL2_CONFIG = "ssl2Only.config";
    public static final String TLS13_CONFIG = "tls13rich.config";
    public static final String DEFAULT_CONFIG = "default.config";
    private static final int COOLDOWN_TIMEOUT_MULTIPLIER = 5;

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean speaksProtocol = false;
    private boolean isHandshaking = false;

    public ConfigSelector(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        this.scannerConfig = scannerConfig;
        this.parallelExecutor = parallelExecutor;
    }

    public boolean findWorkingConfigs() {
        findWorkingConfig();
        if (!scannerConfig.getDtlsDelegate().isDTLS()) {
            findWorkingTls13Config();
        }
        return workingConfig != null || workingTl13Config != null;
    }

    public boolean findWorkingConfig() {
        for (ConfigFilterProfile configProfile : DefaultConfigProfile.getTls12ConfigProfiles()) {
            Config baseConfig = getConfigForProfile(DEFAULT_CONFIG, configProfile);
            if (configWorks(baseConfig)) {
                reportLimitation(configProfile, "TLS 1.2");
                configProfileIdentifier = configProfile.getIdentifier();
                workingConfig = baseConfig.createCopy();
                isHandshaking = true;
                return true;
            }
        }
        return false;
    }

    public Config getConfigForProfile(String startingConfigFile, ConfigFilterProfile configProfile)
            throws ConfigurationException {
        if (scannerConfig.isConfigSearchCooldown()) {
            pauseSearch();
        }
        Config baseConfig =
                Config.createConfig(Config.class.getResourceAsStream(PATH + startingConfigFile));
        ConfigFilter.applyFilterProfile(baseConfig, configProfile.getConfigFilterTypes());
        prepareBaseConfig(baseConfig);
        return baseConfig;
    }

    public void reportLimitation(ConfigFilterProfile configProfile, String versionText) {
        if (configProfile.getConfigFilterTypes().length > 0) {
            LOGGER.warn(
                    "Unable to perform handshake with extensive Config for {}.\nScanning with reduced Config ({}), which may affect the extent of some probes.",
                    versionText,
                    configProfile.getIdentifier());
        }
    }

    public boolean findWorkingTls13Config() {
        for (ConfigFilterProfile configProfile : DefaultConfigProfile.getTls13ConfigProfiles()) {
            Config baseConfig = getConfigForProfile(TLS13_CONFIG, configProfile);
            if (configWorks(baseConfig)) {
                configProfileIdentifierTls13 = configProfile.getIdentifier();
                reportLimitation(configProfile, "TLS 1.3");
                workingTl13Config = baseConfig.createCopy();
                isHandshaking = true;
                return true;
            }
        }
        return false;
    }

    public void prepareBaseConfig(Config baseConfig) throws ConfigurationException {
        applyDelegates(baseConfig);
        applyPerformanceParamters(baseConfig);
        applyScannerConfigParameters(baseConfig);
        repairSni(baseConfig);
        repairConfig(baseConfig);
    }

    private void pauseSearch() {
        try {
            Thread.sleep(COOLDOWN_TIMEOUT_MULTIPLIER * scannerConfig.getTimeout());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Was interrupted - aborting", e);
        }
    }

    private boolean configWorks(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        State state = new State(config, trace);
        parallelExecutor.bulkExecuteStateTasks(state);

        List<Record> reveicedRecords =
                state.getWorkflowTrace().getFirstReceivingAction().getReceivedRecords();
        if ((reveicedRecords != null
                        && !reveicedRecords.isEmpty()
                        && reveicedRecords.get(0) instanceof Record)
                || WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.HELLO_VERIFY_REQUEST)
                || WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO)
                || WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO_DONE)) {
            speaksProtocol = true;
        }
        return trace.executedAsPlanned();
    }

    private void applyPerformanceParamters(Config config) {
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        if (scannerConfig.getDtlsDelegate().isDTLS()) {
            config.setStopTraceAfterUnexpected(false);
        } else {
            config.setStopTraceAfterUnexpected(true);
        }
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
        restrictBasicFeatures(config);
        if (config.getHighestProtocolVersion().isTLS13()) {
            adjustKeyShareFields(config);
        } else {
            adjustEccExtensionsPreTls13(config);
        }
        setDefaultSelectedCipherSuites(config);
        return config;
    }

    public void adjustEccExtensionsPreTls13(Config config) {
        boolean containsEc =
                config.getDefaultClientSupportedCipherSuites().stream()
                        .filter(CipherSuite::isRealCipherSuite)
                        .filter(Predicate.not(CipherSuite::isTLS13))
                        .anyMatch(
                                cipherSuite ->
                                        AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                                                .isEC());
        config.setAddEllipticCurveExtension(containsEc);
        config.setAddECPointFormatExtension(containsEc);
    }

    public void adjustKeyShareFields(Config config) {
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(false);
        if (config.getDefaultClientKeyShareNamedGroups().isEmpty()) {
            config.setDefaultClientKeyShareNamedGroups(
                    new LinkedList<>(config.getDefaultClientNamedGroups()));
        } else {
            config.setDefaultClientKeyShareNamedGroups(
                    config.getDefaultClientKeyShareNamedGroups().stream()
                            .filter(config.getDefaultClientNamedGroups()::contains)
                            .collect(Collectors.toList()));
        }
    }

    public void setDefaultSelectedCipherSuites(Config config) {
        CipherSuite defaultSelectedCipherSuite =
                config.getDefaultClientSupportedCipherSuites().stream()
                        .filter(CipherSuite::isRealCipherSuite)
                        .findFirst()
                        .orElse(config.getDefaultSelectedCipherSuite());
        config.setDefaultSelectedCipherSuite(defaultSelectedCipherSuite);
    }

    public void restrictBasicFeatures(Config config) {
        Config relevantConfig =
                config.getHighestProtocolVersion().isTLS13() ? workingTl13Config : workingConfig;
        if (relevantConfig != null) {
            config.setDefaultClientSupportedCipherSuites(
                    config.getDefaultClientSupportedCipherSuites().stream()
                            .filter(
                                    relevantConfig.getDefaultClientSupportedCipherSuites()
                                            ::contains)
                            .collect(Collectors.toList()));
            config.setDefaultClientNamedGroups(
                    config.getDefaultClientNamedGroups().stream()
                            .filter(relevantConfig.getDefaultClientNamedGroups()::contains)
                            .collect(Collectors.toList()));
            config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                    config.getDefaultClientSupportedSignatureAndHashAlgorithms().stream()
                            .filter(
                                    relevantConfig
                                                    .getDefaultClientSupportedSignatureAndHashAlgorithms()
                                            ::contains)
                            .collect(Collectors.toList()));
        }
    }

    public Config getBaseConfig() {
        return workingConfig.createCopy();
    }

    public Config getSSL2BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + SSL2_CONFIG));
        prepareBaseConfig(config);
        return config;
    }

    public Config getTls13BaseConfig() {
        if (workingTl13Config == null) {
            return Config.createConfig(Config.class.getResourceAsStream(PATH + TLS13_CONFIG));
        }
        return workingTl13Config.createCopy();
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

    public boolean foundWorkingConfig() {
        return workingConfig != null;
    }

    public boolean foundWorkingTls13Config() {
        return workingTl13Config != null;
    }

    public Config getAnyWorkingBaseConfig() {
        if (workingConfig != null) {
            return getBaseConfig();
        }
        if (workingTl13Config != null) {
            return getTls13BaseConfig();
        }
        throw new RuntimeException("No working Config found for tested host");
    }
}
