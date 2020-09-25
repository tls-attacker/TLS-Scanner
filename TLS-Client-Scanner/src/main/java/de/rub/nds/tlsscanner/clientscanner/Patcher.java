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