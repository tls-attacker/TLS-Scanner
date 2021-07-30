/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;

public class SNIUtil {

    private SNIUtil() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static final Logger LOGGER = LogManager.getLogger();

    public static ServerNameIndicationExtensionMessage getSNIFromState(State state) {
        for (ReceivingAction a : state.getWorkflowTrace().getReceivingActions()) {
            ReceivingAction ra = (ReceivingAction) a;
            for (ProtocolMessage m : ra.getReceivedMessages()) {
                if (m instanceof ClientHelloMessage) {
                    return getSNIFromChlo((ClientHelloMessage) m);
                }
            }
        }
        return null;
    }

    public static ServerNameIndicationExtensionMessage getSNIFromChlo(ClientHelloMessage chlo) {
        if (chlo == null) {
            return null;
        }
        return getSNIFromExtensions(chlo.getExtensions());
    }

    public static ServerNameIndicationExtensionMessage getSNIFromExtensions(Iterable<ExtensionMessage> extensions) {
        if (extensions == null) {
            return null;
        }
        for (ExtensionMessage ext : extensions) {
            if (ext instanceof ServerNameIndicationExtensionMessage) {
                return (ServerNameIndicationExtensionMessage) ext;
            }
        }
        return null;
    }

    public static String getServerNameFromSNIExtension(ServerNameIndicationExtensionMessage SNI) {
        if (SNI == null) {
            return null;
        }
        for (ServerNamePair snp : SNI.getServerNameList()) {
            if (snp.getServerNameType().getValue() == 0) {
                return new String(snp.getServerName().getValue());
            } else {
                LOGGER.warn("Received unknown SNI Name Type {}", snp.getServerNameType().getValue());
            }
        }
        return null;
    }
}