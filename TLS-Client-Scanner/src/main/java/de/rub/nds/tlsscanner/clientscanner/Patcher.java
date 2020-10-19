/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner;

import java.security.Security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;

public class Patcher {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void applyPatches() {
        // from GeneralDelegate.applyDelegate
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }
}