/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class DebugExtensionDelegate extends Delegate {

    @Parameter(
            names = "-debugExtension",
            required = false,
            description = "TLS-Attacker debug extension")
    private Boolean debugExtension = false;

    public boolean isDebugExtension() {
        return debugExtension;
    }

    public void setDebugExtension(boolean debugExtension) {
        this.debugExtension = debugExtension;
    }

    public DebugExtensionDelegate() {}

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        if (debugExtension) {
            config.setAddDebugExtension(true);
        }
    }
}
