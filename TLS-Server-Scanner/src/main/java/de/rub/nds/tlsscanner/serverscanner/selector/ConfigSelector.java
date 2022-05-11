/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConfigSelector {

    private ServerScannerConfig scannerConfig;
    private Config workingConfig;

    public static final String PATH = "/configs/";
    public static final String SSL2_CONFIG = "ssl2Only.config";
    public static final String TLS13_CONFIG = "tls13Only.config";
    public static final List<String> CONFIGS = Arrays.asList("default.config", "nice.config");

    private static final Logger LOGGER = LogManager.getLogger();

    public ConfigSelector(ServerScannerConfig scannerConfig) {
        this.scannerConfig = scannerConfig;
    }

    public boolean findWorkingConfig() {
        for (String resource : CONFIGS) {
            Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + resource));
            applyDelegates(config);
            applyPerformanceParamters(config);
            repairConfig(config);
            if (configWorks(config)) {
                workingConfig = config.createCopy();
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

    public Config repairConfig(Config config) {
        if (config.getHighestProtocolVersion().isTLS13()) {
            config.setAddEllipticCurveExtension(true);
            config.setAddECPointFormatExtension(false);
            Iterator iterator = config.getDefaultClientNamedGroups().iterator();
            while (iterator.hasNext()) {
                NamedGroup group = (NamedGroup) iterator.next();
                if (!group.isTls13()) {
                    iterator.remove();
                }
            }
        } else {
            boolean containsEc = false;
            for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
                try {
                    KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
                    if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.isEC()) {
                        containsEc = true;
                        break;
                    }
                } catch (UnsupportedOperationException ex) {
                }
            }
            config.setAddEllipticCurveExtension(containsEc);
            config.setAddECPointFormatExtension(containsEc);
        }
        return config;
    }

    public Config getBaseConfig() {
        return workingConfig.createCopy();
    }

    public Config getSSL2BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + SSL2_CONFIG));
        applyDelegates(config);
        applyPerformanceParamters(config);
        return config;
    }

    public Config getTls13BaseConfig() {
        Config config = Config.createConfig(Config.class.getResourceAsStream(PATH + TLS13_CONFIG));
        applyDelegates(config);
        applyPerformanceParamters(config);
        return config;
    }

    public ServerScannerConfig getScannerConfig() {
        return scannerConfig;
    }

    public void setScannerConfig(ServerScannerConfig scannerConfig) {
        this.scannerConfig = scannerConfig;
    }
}
