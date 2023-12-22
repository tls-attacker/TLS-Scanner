/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.constants;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.Arrays;
import java.util.List;

public enum ApplicationProtocol {
    ECHO,
    STUN,
    TURN,
    VPN_CITRIX,
    VPN_FORTINET,
    COAP,
    HTTP,
    FTP,
    SMTP,
    IMAP,
    LDAP,
    UNKNOWN,
    OTHER;

    public StackConfiguration getExpectedStackConfiguration() {
        // TODO do something smarter than this...
        // This does not distinguish between TLS and DTLS
        // Currently this just serves as a reminder to set the layer configuration for HTTPS
        switch (this) {
            case HTTP:
                return StackConfiguration.HTTPS;
            default:
                return null;
        }
    }

    /**
     * Creates dummy actions which send and receive some application data.
     *
     * @return Actions which send and receive some application data.
     */
    public List<TlsAction> createDummyActions(Config config) {
        // TODO move elsewhere in a more OOP fashion, also keep STARTTLS (ProtocolType) in mind :S
        String alias = config.getDefaultClientConnection().getAlias();
        switch (this) {
            case HTTP:
                SendAction send = new SendAction(alias);
                send.setConfiguredHttpMessages(Arrays.asList(new HttpRequestMessage(config)));
                ReceiveAction recv = new ReceiveAction(alias);
                recv.setExpectedHttpMessages(Arrays.asList(new HttpResponseMessage(config)));
                return Arrays.asList(send, recv);
            case ECHO:
                byte[] msg = "RFC 862".getBytes();
                return Arrays.asList(
                        new SendAction(alias, new ApplicationMessage(msg)),
                        new ReceiveAction(alias, new ApplicationMessage(msg)));

            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
