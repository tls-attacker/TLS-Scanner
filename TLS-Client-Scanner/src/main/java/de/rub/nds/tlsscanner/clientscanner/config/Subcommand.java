/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsattacker.core.config.Config;

public interface Subcommand {
    default void addToJCommander(JCommander jc) {
        jc.addCommand(this);
    }

    void setParsed(JCommander jc) throws ParameterException;

    void applyDelegate(Config config);
}
