/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;

public class ProxyDelegate extends Delegate {

    @Parameter(
            names = "-controlProxy",
            required = false,
            description = "Required by DtlsIpAddressInCookie probe. Syntax: 127.0.0.1:5555")
    private String controlProxy = null;

    @Parameter(
            names = "-dataProxy",
            required = false,
            description = "Required by DtlsIpAddressInCookie probe. Syntax: 127.0.0.1:4444")
    private String dataProxy = null;

    private String extractedControlProxyIp = null;
    private int extractedControlProxyPort = -1;
    private String extractedDataProxyIp = null;
    private int extractedDataProxyPort = -1;

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}

    public void extractParameters() {
        if (controlProxy == null || dataProxy == null) {
            throw new ParameterException("Control proxy or/and data proxy null");
        }

        controlProxy = IDN.toASCII(controlProxy);
        URI uriControlProxy;
        try {
            // Add a dummy protocol
            uriControlProxy = new URI("my://" + controlProxy);
        } catch (URISyntaxException ex) {
            throw new ParameterException(
                    "Could not parse control proxy '" + controlProxy + "'", ex);
        }
        if (uriControlProxy.getHost() == null) {
            throw new ParameterException("Provided control proxy seems invalid:" + controlProxy);
        }
        if (uriControlProxy.getPort() <= 0) {
            throw new ParameterException("Provided control proxy seems invalid:" + controlProxy);
        } else {
            extractedControlProxyPort = uriControlProxy.getPort();
        }
        extractedControlProxyIp = uriControlProxy.getHost();

        dataProxy = IDN.toASCII(dataProxy);
        URI uriDataProxy;
        try {
            // Add a dummy protocol
            uriDataProxy = new URI("my://" + dataProxy);
        } catch (URISyntaxException ex) {
            throw new ParameterException("Could not parse data proxy '" + dataProxy + "'", ex);
        }
        if (uriDataProxy.getHost() == null) {
            throw new ParameterException("Provided data proxy seems invalid:" + dataProxy);
        }
        if (uriDataProxy.getPort() <= 0) {
            throw new ParameterException("Provided data proxy seems invalid:" + dataProxy);
        } else {
            extractedDataProxyPort = uriDataProxy.getPort();
        }
        extractedDataProxyIp = uriDataProxy.getHost();
    }

    public String getExtractedControlProxyIp() {
        if (controlProxy != null && extractedControlProxyIp == null) {
            extractParameters();
        }
        return extractedControlProxyIp;
    }

    public int getExtractedControlProxyPort() {
        if (controlProxy != null && extractedControlProxyPort == -1) {
            extractParameters();
        }
        return extractedControlProxyPort;
    }

    public String getExtractedDataProxyIp() {
        if (dataProxy != null && extractedDataProxyIp == null) {
            extractParameters();
        }
        return extractedDataProxyIp;
    }

    public int getExtractedDataProxyPort() {
        if (dataProxy != null && extractedDataProxyPort == -1) {
            extractParameters();
        }
        return extractedDataProxyPort;
    }
}
