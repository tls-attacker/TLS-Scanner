/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;

public class SNIUtil {

    private SNIUtil() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static final Logger LOGGER = LogManager.getLogger();

    public static ServerNameIndicationExtensionMessage getSNIFromExtensions(Iterable<ExtensionMessage> extensions) {
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