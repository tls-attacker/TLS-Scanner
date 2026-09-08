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
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.starttls.StarttlsCapabilityDiscoveryDecision;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A {@link ConfigSelector} for targets scanned behind a STARTTLS upgrade.
 *
 * <p>The plain selector searches once and is done. A STARTTLS target can refuse the search for a
 * reason no config profile addresses: servers that enforce the full command sequence from their RFC
 * reject the bare upgrade command, so every profile fails identically. This selector recognises
 * that refusal and searches a second time with the protocol's capability-discovery exchange turned
 * on, then keeps that variant on every config it hands out.
 */
public class StarttlsConfigSelector extends ConfigSelector {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Whether the target turned out to need its capability-discovery exchange. Learned once by
     * {@link #findWorkingConfigs()} and stamped onto every config this selector hands out, so the
     * probes that follow build the working upgrade instead of repeating the refused one.
     */
    private boolean targetRequiresCapabilityDiscovery = false;

    /**
     * The reply the target sent to the minimal upgrade command, which decides whether running the
     * capability exchange is worth a second attempt.
     */
    private String starttlsMinimalUpgradeReply = null;

    /**
     * Constructs a new StarttlsConfigSelector with the specified scanner configuration and
     * executor.
     *
     * @param scannerConfig the server scanner configuration
     * @param parallelExecutor the parallel executor for running test handshakes
     */
    public StarttlsConfigSelector(
            ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(scannerConfig, parallelExecutor);
    }

    /**
     * Runs the ordinary search and, if it found nothing because the target refused the bare
     * upgrade, runs it once more with the capability-discovery exchange.
     *
     * @return true if either attempt found a working configuration
     */
    @Override
    public boolean findWorkingConfigs() {
        if (super.findWorkingConfigs()) {
            return true;
        }
        return retryWithCapabilityDiscovery();
    }

    /**
     * Retries the config search with the protocol's capability-discovery exchange, for a target
     * that accepted nothing so far.
     *
     * <p>Servers that took the minimal upgrade never reach this, so the extra connections are only
     * spent where they are the difference between a scan and no scan.
     *
     * <p>The retry is sequential rather than nested in the profile loop on purpose: nesting would
     * double the connections for every target, while this only repeats the search when the first
     * variant found nothing at all.
     *
     * @return true if the discovery variant found a working configuration
     */
    private boolean retryWithCapabilityDiscovery() {
        StarttlsType starttlsType = getScannerConfig().getStartTlsDelegate().getStarttlsType();
        if (targetRequiresCapabilityDiscovery
                || !StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        starttlsType, starttlsMinimalUpgradeReply)) {
            return false;
        }
        LOGGER.info(
                "Target refused the direct {} upgrade with \"{}\", retrying with its capability "
                        + "discovery exchange",
                starttlsType,
                starttlsMinimalUpgradeReply.trim());
        targetRequiresCapabilityDiscovery = true;
        return super.findWorkingConfigs();
    }

    /**
     * Repairs the config as the base selector does, then stamps on the upgrade variant this target
     * accepted.
     *
     * <p>This belongs to the repair step rather than to a one-off patch of the base config: probes
     * derive their own configs, and a config that lost the learned variant would repeat the upgrade
     * the target already refused.
     *
     * @param config the configuration to repair
     * @return the repaired configuration
     */
    @Override
    public Config repairConfig(Config config) {
        super.repairConfig(config);
        config.setStarttlsUseCapabilityDiscovery(targetRequiresCapabilityDiscovery);
        return config;
    }

    /**
     * Keeps the refusal the target sent to the minimal upgrade, which decides whether the
     * capability exchange is worth a second attempt. Only the first is kept; later connections
     * repeat it.
     *
     * @param trace an executed trace
     */
    @Override
    protected void onTraceExecuted(WorkflowTrace trace) {
        if (targetRequiresCapabilityDiscovery || starttlsMinimalUpgradeReply != null) {
            return;
        }
        starttlsMinimalUpgradeReply =
                StarttlsCapabilityDiscoveryDecision.getMinimalUpgradeReply(trace);
    }

    @Override
    public boolean isStarttlsCapabilityDiscoveryRequired() {
        return targetRequiresCapabilityDiscovery;
    }
}
