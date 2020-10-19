/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.dispatcher.sni;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.SNIUtil;

public class SNIDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private Map<String, IDispatcher> forwardRules;

    public SNIDispatcher(Map<String, IDispatcher> rules) {
        forwardRules = new HashMap<>(rules);
    }

    public SNIDispatcher() {
        forwardRules = new HashMap<>();
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        ServerNameIndicationExtensionMessage SNI = SNIUtil
                .getSNIFromExtensions(dispatchInformation.chlo.getExtensions());
        if (SNI == null) {
            LOGGER.debug("Did not find SNI Extension");
            throw new NoSNIExtensionException();
        }
        String hostname = SNIUtil.getServerNameFromSNIExtension(SNI);
        if (hostname == null) {
            LOGGER.debug("Did not find Name in SNI Extension");
            throw new NoSNINameException();
        }
        LOGGER.debug("Got '{}'", hostname);
        return dispatch(state, dispatchInformation, hostname);
    }

    public RuleMatch lookupRule(String hostname) {
        LOGGER.trace("Trying to find rule for {}", hostname);
        int index = hostname.length();
        while (index > -1) {
            index = hostname.lastIndexOf('.', index - 1);
            String hostnameTry = hostname.substring(index + 1);
            IDispatcher next = forwardRules.get(hostnameTry);
            if (next != null) {
                String hostnameRemaining = "";
                if (index > -1) {
                    hostnameRemaining = hostname.substring(0, index);
                }
                LOGGER.trace("Found rule for {} (remaining: {})", hostnameTry, hostnameRemaining);
                return new RuleMatch(next, hostnameTry, hostnameRemaining);
            } else {
                LOGGER.trace("Hostname {} did not match", hostnameTry);
            }
        }
        LOGGER.debug("Did not find rule for {}", hostname);
        return null;
    }

    public ClientProbeResult dispatch(State state, DispatchInformation dispatchInformation, String hostname)
            throws DispatchException {
        RuleMatch next = lookupRule(hostname);
        if (next == null) {
            throw new UnknownSNINameException();
        }
        synchronized (dispatchInformation.additionalInformation) {
            dispatchInformation.additionalInformation.put(
                    SNIDispatcher.class,
                    new SNIDispatchInformation(
                            dispatchInformation.getAdditionalInformation(SNIDispatcher.class,
                                    SNIDispatchInformation.class),
                            this, next.matchedHostnameSuffix, next.remainingHostnamePrefix));
        }
        return next.nextDispatcher.execute(state, dispatchInformation);
    }

    public void registerRule(String suffix, IDispatcher dispatcher) {
        forwardRules.put(suffix, dispatcher);
    }

    public static class RuleMatch {
        public final IDispatcher nextDispatcher;
        public final String matchedHostnameSuffix;
        public final String remainingHostnamePrefix;

        public RuleMatch(IDispatcher nextDispatcher, String matchedHostnameSuffix, String remainingHostnamePrefix) {
            this.nextDispatcher = nextDispatcher;
            this.matchedHostnameSuffix = matchedHostnameSuffix;
            this.remainingHostnamePrefix = remainingHostnamePrefix;
        }
    }

    public static class SNIDispatchInformation {
        public final SNIDispatchInformation previous;
        public final SNIDispatcher dispatcher;
        public final String handledHostname;
        public final String remainingHostname;

        public SNIDispatchInformation(SNIDispatchInformation previous, SNIDispatcher dispatcher,
                String handledHostname, String remainingHostname) {
            this.previous = previous;
            this.dispatcher = dispatcher;
            this.handledHostname = handledHostname;
            this.remainingHostname = remainingHostname;
        }
    }

    public static class SNIDispatchException extends DispatchException {

    }

    public static class NoSNIExtensionException extends SNIDispatchException {

    }

    public static class NoSNINameException extends SNIDispatchException {

    }

    public static class UnknownSNINameException extends SNIDispatchException {

    }

}