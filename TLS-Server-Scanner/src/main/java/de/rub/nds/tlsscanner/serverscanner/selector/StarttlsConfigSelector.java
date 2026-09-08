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

/** A {@link ConfigSelector} for targets scanned behind a STARTTLS upgrade. */
public class StarttlsConfigSelector extends ConfigSelector {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean targetRequiresCapabilityDiscovery = false;

    private String starttlsMinimalUpgradeReply = null;

    public StarttlsConfigSelector(
            ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(scannerConfig, parallelExecutor);
    }

    @Override
    public boolean findWorkingConfigs() {
        if (super.findWorkingConfigs()) {
            return true;
        }
        return retryWithCapabilityDiscovery();
    }

    /**
     * Sequential rather than nested in the profile loop: nesting would double the connections for
     * every target, while this only repeats the search when the first variant found nothing.
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
     * Stamps on the learned upgrade variant. Part of the repair step rather than a one-off patch of
     * the base config: probes derive their own configs, and one that lost the variant would repeat
     * the upgrade the target already refused.
     */
    @Override
    public Config repairConfig(Config config) {
        super.repairConfig(config);
        config.setStarttlsUseCapabilityDiscovery(targetRequiresCapabilityDiscovery);
        return config;
    }

    /** Keeps the first refusal only; later connections repeat it. */
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
