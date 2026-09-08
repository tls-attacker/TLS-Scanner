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
import java.util.regex.Pattern;

/** Decides whether a STARTTLS target's capability-discovery exchange is worth a second attempt. */
public final class StarttlsCapabilityDiscoveryDecision {

    private StarttlsCapabilityDiscoveryDecision() {}

    /**
     * True only for a refusal that complains about the order of the commands. Anything else,
     * including no reply, is no evidence that discovery would help.
     */
    public static boolean shouldRetryWithDiscovery(StarttlsType type, String upgradeReply) {
        if (upgradeReply == null) {
            return false;
        }
        if (type == null || !type.hasDialect()) {
            return false;
        }
        String badSequenceRegex = type.getBadSequenceRegex();
        if (badSequenceRegex == null) {
            return false;
        }
        return Pattern.compile(badSequenceRegex).matcher(upgradeReply.trim()).find();
    }

    /**
     * Searched from the end because the upgrade reply is the last thing read before the handshake,
     * which keeps this independent of the variant that built the trace and of the exchange length.
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
