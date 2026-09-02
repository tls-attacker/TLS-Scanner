/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.starttls;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveRegexTextAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.StartTlsDialect;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Reads a STARTTLS target's refusal to decide whether its capability-discovery exchange is worth a
 * second attempt.
 *
 * <p>TLS-Attacker builds both upgrade variants and picks between them from the config. This only
 * answers the question the config cannot: whether the target we are looking at needs the longer
 * one. What each protocol says is the dialect's business, so nothing here names one.
 */
public final class StarttlsCapabilityDiscovery {

    private StarttlsCapabilityDiscovery() {}

    /**
     * Whether the target should be retried with its capability-discovery exchange.
     *
     * <p>True only when the protocol has a dialect that can tell a complaint about the order of the
     * commands apart from a refusal of the upgrade itself, and the target answered with the former.
     * Anything else, including no reply at all, is not retried: there is no evidence discovery
     * would help.
     *
     * @param type the STARTTLS type being scanned
     * @param upgradeReply the text the target sent in response to the upgrade command
     * @return true if the discovery exchange is worth attempting
     */
    public static boolean shouldRetryWithDiscovery(StarttlsType type, String upgradeReply) {
        if (upgradeReply == null) {
            return false;
        }
        return StartTlsDialect.forType(type)
                .map(StartTlsDialect::badSequenceRegex)
                .filter(Objects::nonNull)
                .filter(regex -> Pattern.compile(regex).matcher(upgradeReply.trim()).find())
                .isPresent();
    }

    /**
     * Returns the last reply the target sent during a text-based STARTTLS prefix, or null if it
     * never sent one.
     *
     * <p>The upgrade reply is the last thing read before the trace either gives up or starts the
     * handshake, so searching from the end finds it without counting the actions in front of it.
     * That keeps this independent of which upgrade variant built the trace and of how long a given
     * protocol's exchange is.
     *
     * @param workflowTrace an executed trace
     * @return the received upgrade reply, or null
     */
    public static String getMinimalUpgradeReply(WorkflowTrace workflowTrace) {
        List<TlsAction> actions = workflowTrace.getTlsActions();
        for (int i = actions.size() - 1; i >= 0; i--) {
            if (actions.get(i) instanceof ReceiveRegexTextAction receiveAction
                    && receiveAction.getReceivedText() != null) {
                return receiveAction.getReceivedText();
            }
        }
        return null;
    }
}
