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
import de.rub.nds.tlsattacker.core.workflow.action.SendTextAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.List;
import java.util.Set;

/**
 * The capability-discovery exchange a STARTTLS protocol offers, for servers that refuse the bare
 * upgrade command.
 *
 * <p>TLS-Attacker builds the minimal upgrade: read the greeting, send the upgrade command, expect
 * the success code. Most servers accept that. Some enforce the full command sequence from their RFC
 * and answer the bare upgrade with a permanent error, and those need the capability exchange (FTP
 * {@code FEAT}, IMAP {@code CAPABILITY}, SMTP {@code EHLO}) run first.
 *
 * <p>Which of the two a server needs cannot be known before asking it, so {@link
 * de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector} learns it once per scan and reuses
 * the answer.
 */
public enum StarttlsCapabilityDiscovery {
    FTP(
            StarttlsType.FTP,
            "^220 ",
            "FEAT\r\n",
            "^211 ",
            "AUTH TLS",
            "AUTH TLS\r\n",
            "^234 ",
            // RFC 4217 gives AUTH its own refusals: 534 denied for policy reasons and 431 the
            // requested security mechanism is unavailable. RFC 959 adds 503 bad sequence, 530 not
            // logged in and 421 service unavailable. All of them reject the upgrade for where it
            // appeared in the conversation or for the state the connection is in, not for what it
            // asked, so running FEAT first can still get there. 500/502/504 mean the command
            // itself is unknown or unsupported, and no amount of discovery changes that.
            Set.of("534", "431", "503", "530", "421"));

    /** Permanent and transient error replies, which every supported protocol reports as 4xx/5xx. */
    private static final String ERROR_REPLY_REGEX = "^[45]\\d\\d ";

    private final StarttlsType type;
    private final String greetingRegex;
    private final String discoveryCommand;
    private final String discoveryReplyRegex;
    private final String capability;
    private final String upgradeCommand;
    private final String upgradeSuccessRegex;
    private final Set<String> retryableRefusalCodes;

    StarttlsCapabilityDiscovery(
            StarttlsType type,
            String greetingRegex,
            String discoveryCommand,
            String discoveryReplyRegex,
            String capability,
            String upgradeCommand,
            String upgradeSuccessRegex,
            Set<String> retryableRefusalCodes) {
        this.type = type;
        this.greetingRegex = greetingRegex;
        this.discoveryCommand = discoveryCommand;
        this.discoveryReplyRegex = discoveryReplyRegex;
        this.capability = capability;
        this.upgradeCommand = upgradeCommand;
        this.upgradeSuccessRegex = upgradeSuccessRegex;
        this.retryableRefusalCodes = retryableRefusalCodes;
    }

    /**
     * Returns the discovery exchange defined for the given STARTTLS type, or null if the type has
     * none yet. Callers must treat null as "only the minimal upgrade is available".
     *
     * @param type the STARTTLS type to look up
     * @return the matching discovery exchange, or null
     */
    public static StarttlsCapabilityDiscovery forType(StarttlsType type) {
        for (StarttlsCapabilityDiscovery discovery : values()) {
            if (discovery.type == type) {
                return discovery;
            }
        }
        return null;
    }

    /**
     * Prepends the discovery exchange and the upgrade command to the given trace, replacing the
     * minimal upgrade TLS-Attacker would have built.
     *
     * <p>The discovery reply is not matched against the capability here. A server that lists no
     * upgrade simply fails the upgrade command that follows, which is the same outcome by a shorter
     * path, and it keeps the trace free of control flow.
     *
     * @param workflowTrace the trace to prepend to
     */
    public void prependTo(WorkflowTrace workflowTrace) {
        ReceiveRegexTextAction discoveryReply = new ReceiveRegexTextAction(discoveryReplyRegex);
        discoveryReply.setAbortRegex(ERROR_REPLY_REGEX);
        ReceiveRegexTextAction upgradeReply = new ReceiveRegexTextAction(upgradeSuccessRegex);
        upgradeReply.setAbortRegex(ERROR_REPLY_REGEX);

        int index = 0;
        workflowTrace.addTlsAction(index++, new ReceiveRegexTextAction(greetingRegex));
        workflowTrace.addTlsAction(index++, new SendTextAction(discoveryCommand, null));
        workflowTrace.addTlsAction(index++, discoveryReply);
        workflowTrace.addTlsAction(index++, new SendTextAction(upgradeCommand, null));
        workflowTrace.addTlsAction(index, upgradeReply);
    }

    /**
     * Returns the number of actions {@link #prependTo(WorkflowTrace)} adds, so callers can strip
     * the minimal upgrade TLS-Attacker built before prepending this one.
     *
     * @return the action count
     */
    public int getActionCount() {
        return 5;
    }

    /**
     * Whether the refusal the target sent is worth retrying with this discovery exchange.
     *
     * <p>A server that rejected the bare upgrade because it came at the wrong point in the
     * conversation can still accept it after the discovery command. A server that does not
     * implement the upgrade at all answers the same request the same way however it is reached, so
     * retrying only costs a connection. Anything that is not a refusal reply, including no reply,
     * is not retried either: there is no evidence discovery would help.
     *
     * @param upgradeReply the text the target sent in response to the upgrade command
     * @return true if the discovery exchange is worth attempting
     */
    public boolean isRetryableRefusal(String upgradeReply) {
        if (upgradeReply == null) {
            return false;
        }
        String trimmed = upgradeReply.trim();
        if (trimmed.length() < 3) {
            return false;
        }
        return retryableRefusalCodes.contains(trimmed.substring(0, 3));
    }

    /**
     * Returns the reply the target sent to the minimal upgrade command, or null if the trace never
     * got that far.
     *
     * <p>Reads the last action of the STARTTLS prefix TLS-Attacker builds, which is the upgrade
     * reply for every protocol it supports.
     *
     * @param workflowTrace an executed trace built with the minimal upgrade
     * @param minimalActionCount how many actions that minimal upgrade occupies
     * @return the received upgrade reply, or null
     */
    public static String getMinimalUpgradeReply(
            WorkflowTrace workflowTrace, int minimalActionCount) {
        List<TlsAction> actions = workflowTrace.getTlsActions();
        if (actions.size() < minimalActionCount) {
            return null;
        }
        TlsAction action = actions.get(minimalActionCount - 1);
        if (action instanceof ReceiveRegexTextAction) {
            return ((ReceiveRegexTextAction) action).getReceivedText();
        }
        return null;
    }

    public StarttlsType getType() {
        return type;
    }

    public String getCapability() {
        return capability;
    }
}
