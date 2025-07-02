/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;

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

    /**
     * Applies the delegate configuration to the provided Config object. This implementation does
     * not modify the config.
     *
     * @param config the Config object to apply settings to
     * @throws ConfigurationException if configuration fails
     */
    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}

    /**
     * Gets the ALPN (Application-Layer Protocol Negotiation) options.
     *
     * @return the ALPN options string, or null if not configured
     */
    public String getAlpnOptions() {
        return alpnOptions;
    }

    /**
     * Gets the session resumption options.
     *
     * @return the resumption options string, or null if not configured
     */
    public String getResumptionOptions() {
        return resumptionOptions;
    }

    /**
     * Gets the SNI (Server Name Indication) options with the specified domain. Replaces the domain
     * marker in the SNI options with the actual domain.
     *
     * @param domain the domain name to use for SNI
     * @return the SNI options with domain replaced, or null if not configured or missing marker
     */
    public String getSniOptions(String domain) {
        if (sniOptions == null || !sniOptions.contains(SNI_REPLACEMENT_MARKER)) {
            return null;
        }
        return sniOptions.replace(SNI_REPLACEMENT_MARKER, domain);
    }
}
