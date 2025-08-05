/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
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

/**
 * Responsible for selecting and preparing TLS configurations for scanning operations. This class
 * finds working configurations by testing various filter profiles and prepares them for use in TLS
 * handshakes and protocol analysis.
 */
public class ConfigSelector {

    /**
     * Returns the identifier of the configuration profile used for TLS 1.2 and earlier.
     *
     * @return the configuration profile identifier, or null if no working config was found
     */
    public String getConfigProfileIdentifier() {
        return configProfileIdentifier;
    }

    /**
     * Returns the identifier of the configuration profile used for TLS 1.3.
     *
     * @return the TLS 1.3 configuration profile identifier, or null if no working config was found
     */
    public String getConfigProfileIdentifierTls13() {
        return configProfileIdentifierTls13;
    }

    private final ServerScannerConfig scannerConfig;
    private final ParallelExecutor parallelExecutor;
    private Config workingConfig;
    private String configProfileIdentifier;
    private Config workingTl13Config;
    private String configProfileIdentifierTls13;

    /** Path to configuration files resource directory */
    public static final String PATH = "/configs/";

    /** SSL2-specific configuration filename */
    public static final String SSL2_CONFIG = "ssl2Only.config";

    /** TLS 1.3 rich configuration filename */
    public static final String TLS13_CONFIG = "tls13rich.config";

    /** Default configuration filename */
    public static final String DEFAULT_CONFIG = "default.config";

    private static final int COOLDOWN_TIMEOUT_MULTIPLIER = 5;

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean speaksProtocol = false;
    private boolean isHandshaking = false;
    private boolean quicRetryRequired = false;

    /**
     * Constructs a new ConfigSelector with the specified scanner configuration and executor.
     *
     * @param scannerConfig the server scanner configuration
     * @param parallelExecutor the parallel executor for running test handshakes
     */
    public ConfigSelector(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        this.scannerConfig = scannerConfig;
        this.parallelExecutor = parallelExecutor;
    }

    /**
     * Attempts to find working configurations for both (D)TLS 1.2 and TLS 1.3 protocols as needed
     * by the protocol configuration.
     *
     * @return true if at least one working configuration was found, false otherwise
     */
    public boolean findWorkingConfigs() {
        if (!scannerConfig.getQuicDelegate().isQuic()) {
            findWorkingConfig();
        }
        if (!scannerConfig.getDtlsDelegate().isDTLS()) {
            findWorkingTls13Config();
        }
        return workingConfig != null || workingTl13Config != null;
    }

    /**
     * Searches for a working (D)TLS 1.2 configuration by testing various filter profiles. Iterates
     * through default profiles until a working configuration is found.
     *
     * @return true if a working configuration was found, false otherwise
     */
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

    /**
     * Creates a configuration based on the specified starting configuration file and applies the
     * given filter profile.
     *
     * @param startingConfigFile the base configuration file to start with
     * @param configProfile the filter profile to apply
     * @return the prepared configuration
     * @throws ConfigurationException if the configuration cannot be created or prepared
     */
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

    /**
     * Reports limitations based on the applied configuration filter profile. Logs a warning if
     * certain features had to be filtered out to achieve a working configuration.
     *
     * @param configProfile the filter profile that was applied
     * @param versionText the TLS version description (e.g., "TLS 1.2", "TLS 1.3")
     */
    public void reportLimitation(ConfigFilterProfile configProfile, String versionText) {
        if (configProfile.getConfigFilterTypes().length > 0) {
            LOGGER.warn(
                    "Unable to perform handshake with extensive Config for {}.\nScanning with reduced Config ({}), which may affect the extent of some probes.",
                    versionText,
                    configProfile.getIdentifier());
        }
    }

    /**
     * Searches for a working TLS 1.3 configuration by testing various filter profiles specific to
     * TLS 1.3. Iterates through TLS 1.3 profiles until a working configuration is found.
     *
     * @return true if a working TLS 1.3 configuration was found, false otherwise
     */
    public boolean findWorkingTls13Config() {
        for (ConfigFilterProfile configProfile : DefaultConfigProfile.getTls13ConfigProfiles()) {
            Config baseConfig = getConfigForProfile(TLS13_CONFIG, configProfile);
            baseConfig.setQuicRetryFlowRequired(false);
            if (configWorks(baseConfig)) {
                configProfileIdentifierTls13 = configProfile.getIdentifier();
                reportLimitation(configProfile, "TLS 1.3");
                workingTl13Config = baseConfig.createCopy();
                isHandshaking = true;
                return true;
            } else if (scannerConfig.getQuicDelegate().isQuic()) {
                baseConfig.setQuicRetryFlowRequired(true);
                if (configWorks(baseConfig)) {
                    configProfileIdentifierTls13 = configProfile.getIdentifier();
                    reportLimitation(configProfile, "TLS 1.3");
                    workingTl13Config = baseConfig.createCopy();
                    isHandshaking = true;
                    quicRetryRequired = true;
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Prepares a base configuration for use in scanning by applying scanner-specific settings and
     * adjustments. This includes setting connection parameters, timeouts, and protocol-specific
     * configurations.
     *
     * @param baseConfig the configuration to prepare
     * @throws ConfigurationException if the configuration cannot be properly prepared
     */
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
        if (!scannerConfig.isDoNotSendSNIExtension()
                && (!IPAddress.isValid(config.getDefaultClientConnection().getHostname())
                        || scannerConfig.getClientDelegate().getSniHostname() != null)) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }
    }

    /**
     * Repairs a configuration by adjusting various settings to ensure compatibility. This includes
     * handling ECC extensions, key share fields, cipher suite selection, and basic feature
     * restrictions.
     *
     * @param config the configuration to repair
     * @return the repaired configuration
     */
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

    /**
     * Adjusts ECC-related extensions for pre-(D)TLS 1.3 configurations. Ensures that ECC point
     * formats and elliptic curves extensions are properly configured based on the selected cipher
     * suites.
     *
     * @param config the configuration to adjust
     */
    public void adjustEccExtensionsPreTls13(Config config) {
        boolean containsEc =
                config.getDefaultClientSupportedCipherSuites().stream()
                        .filter(CipherSuite::isRealCipherSuite)
                        .filter(Predicate.not(CipherSuite::isTls13))
                        .anyMatch(cipherSuite -> cipherSuite.getKeyExchangeAlgorithm().isEC());
        config.setAddEllipticCurveExtension(containsEc);
        config.setAddECPointFormatExtension(containsEc);
    }

    /**
     * Adjusts key share fields in the configuration based on the highest supported protocol
     * version. For TLS 1.3, it configures appropriate key share entries.
     *
     * @param config the configuration to adjust
     */
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

    /**
     * Sets default selected cipher suites based on the configuration's supported cipher suites.
     * This ensures that the selected cipher suites are consistent with what's supported.
     *
     * @param config the configuration to update
     */
    public void setDefaultSelectedCipherSuites(Config config) {
        CipherSuite defaultSelectedCipherSuite =
                config.getDefaultClientSupportedCipherSuites().stream()
                        .filter(CipherSuite::isRealCipherSuite)
                        .findFirst()
                        .orElse(config.getDefaultSelectedCipherSuite());
        config.setDefaultSelectedCipherSuite(defaultSelectedCipherSuite);
    }

    /**
     * Restricts basic features in the configuration by disabling certain extensions and features
     * that might interfere with scanning operations. This includes disabling session tickets,
     * heartbeat, and other optional features.
     *
     * @param config the configuration to restrict
     */
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

    /**
     * Returns the base working configuration for (D)TLS 1.2 and earlier protocols.
     *
     * @return the working configuration, or null if none was found
     */
    public Config getBaseConfig() {
        return workingConfig.createCopy();
    }

    /**
     * Returns an SSL2-specific base configuration. Creates a new configuration from the SSL2
     * configuration file and prepares it for use.
     *
     * @return the prepared SSL2 configuration
     * @throws ConfigurationException if the configuration cannot be created or prepared
     */
    public Config getSSL2BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + SSL2_CONFIG));
        prepareBaseConfig(config);
        return config;
    }

    /**
     * Returns the base working configuration for TLS 1.3.
     *
     * @return the working TLS 1.3 configuration, or null if none was found
     */
    public Config getTls13BaseConfig() {
        if (workingTl13Config == null) {
            return Config.createConfig(Config.class.getResourceAsStream(PATH + TLS13_CONFIG));
        }
        return workingTl13Config.createCopy();
    }

    /**
     * Indicates whether the scanner successfully performed a handshake with the target server.
     *
     * @return true if a successful handshake was achieved, false otherwise
     */
    public boolean isIsHandshaking() {
        return isHandshaking;
    }

    /**
     * Indicates whether the target server speaks the TLS protocol (i.e., responds to TLS messages
     * even if handshaking fails).
     *
     * @return true if the server responds to TLS protocol messages, false otherwise
     */
    public boolean isSpeaksProtocol() {
        return speaksProtocol;
    }

    /**
     * Indicates whether a QUIC retry is required for the connection.
     *
     * @return true if QUIC retry is required, false otherwise
     */
    public boolean isQuicRetryRequired() {
        return quicRetryRequired;
    }

    /**
     * Returns the scanner configuration used by this selector.
     *
     * @return the server scanner configuration
     */
    public ServerScannerConfig getScannerConfig() {
        return scannerConfig;
    }

    /**
     * Checks whether a working smaller equal to TLS 1.2 configuration was found.
     *
     * @return true if a working configuration exists, false otherwise
     */
    public boolean foundWorkingConfig() {
        return workingConfig != null;
    }

    /**
     * Checks whether a working TLS 1.3 configuration was found.
     *
     * @return true if a working TLS 1.3 configuration exists, false otherwise
     */
    public boolean foundWorkingTls13Config() {
        return workingTl13Config != null;
    }

    /**
     * Returns any available working configuration, preferring TLS 1.3 over TLS 1.2.
     *
     * @return a working configuration (TLS 1.3 preferred), or null if none exists
     */
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
