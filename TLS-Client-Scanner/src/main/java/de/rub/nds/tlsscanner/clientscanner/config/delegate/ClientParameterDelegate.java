/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.config.delegate;

import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class ClientParameterDelegate extends Delegate {

    private static final String SNI_REPLACEMENT_MARKER = "[domain]";

    @Parameter(
            names = "-alpnOptions",
            required = false,
            description =
                    "If needed, the shell command option(s) that should be added to the run command to enable Application-Layer Protocol Negotiation")
    private String alpnOptions = null;

    @Parameter(
            names = "-resumptionOptions",
            required = false,
            description =
                    "If needed, the shell command option(s) that should be added to the run command to enable session resumption")
    private String resumptionOptions = null;

    @Parameter(
            names = "-sniOptions",
            required = false,
            description =
                    "If needed, the shell command option(s) that should be added to the run command to enable Server Name Indication capabilities. The domain to use must be marked with '"
                            + SNI_REPLACEMENT_MARKER
                            + "'")
    private String sniOptions = null;

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}

    public String getAlpnOptions() {
        return alpnOptions;
    }

    public String getResumptionOptions() {
        return resumptionOptions;
    }

    public String getSniOptions(String domain) {
        if (sniOptions == null) {
            return null;
        }
        return sniOptions.replace(SNI_REPLACEMENT_MARKER, domain);
    }
}
