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
import java.util.List;

/**
 * Reads a STARTTLS target's refusal to decide whether its capability-discovery exchange is worth a
 * second attempt.
 *
 * <p>TLS-Attacker builds both upgrade variants and picks between them from the config. This only
 * answers the question the config cannot: whether the target we are looking at needs the longer
 * one.
 */
public final class StarttlsCapabilityDiscovery {

    /**
     * The only refusal that says the upgrade could still succeed in a different order. RFC 959
     * defines 503 as a bad sequence of commands, which is exactly what a server means when it wants
     * its capability exchange run first. Every other error either rejects the command itself (500,
     * 502, 504), or describes a condition the exchange does not change (421, 431, 530), so retrying
     * those would only cost a connection.
     */
    private static final String BAD_SEQUENCE_STATUS = "503";

    /** Greeting, upgrade command and upgrade reply, the trace TLS-Attacker builds by default. */
    private static final int MINIMAL_UPGRADE_ACTION_COUNT = 3;

    private StarttlsCapabilityDiscovery() {}

    /**
     * Whether the target should be retried with its capability-discovery exchange.
     *
     * <p>True only for a protocol TLS-Attacker can build the longer upgrade for, and only when the
     * target refused with a bad sequence. Anything else, including no reply at all, is not retried:
     * there is no evidence discovery would help.
     *
     * @param type the STARTTLS type being scanned
     * @param upgradeReply the text the target sent in response to the upgrade command
     * @return true if the discovery exchange is worth attempting
     */
    public static boolean shouldRetryWithDiscovery(StarttlsType type, String upgradeReply) {
        return type == StarttlsType.FTP
                && upgradeReply != null
                && upgradeReply.trim().startsWith(BAD_SEQUENCE_STATUS);
    }

    /**
     * Returns the reply the target sent to the upgrade command of a minimal-variant trace, or null
     * if the trace never got that far.
     *
     * <p>The upgrade reply is the third action of the prefix TLS-Attacker builds for the minimal
     * variant. The discovery variant puts its capability exchange in between, so this must only be
     * called on a trace built without discovery; the index would otherwise name the discovery reply
     * instead.
     *
     * @param workflowTrace an executed trace built with the minimal upgrade
     * @return the received upgrade reply, or null
     */
    public static String getMinimalUpgradeReply(WorkflowTrace workflowTrace) {
        List<TlsAction> actions = workflowTrace.getTlsActions();
        if (actions.size() < MINIMAL_UPGRADE_ACTION_COUNT) {
            return null;
        }
        TlsAction action = actions.get(MINIMAL_UPGRADE_ACTION_COUNT - 1);
        if (action instanceof ReceiveRegexTextAction) {
            return ((ReceiveRegexTextAction) action).getReceivedText();
        }
        return null;
    }
}
