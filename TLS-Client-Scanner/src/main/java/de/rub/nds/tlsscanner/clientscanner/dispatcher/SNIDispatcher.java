package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
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
        String name = SNIUtil.getServerNameFromSNIExtension(SNI);
        if (name == null) {
            LOGGER.debug("Did not find Name in SNI Extension");
            throw new NoSNINameException();
        }
        LOGGER.debug("Got '{}'", name);
        IDispatcher next = null;
        synchronized (forwardRules) {
            if (!forwardRules.containsKey(name)) {
                LOGGER.debug("Did not find rule for {}", name);
                throw new UnknownSNINameException();
            } else {
                next = forwardRules.get(name);
            }
        }
        return next.execute(state, dispatchInformation);
    }

    public class SNIDispatchException extends DispatchException {

    }

    public class NoSNIExtensionException extends SNIDispatchException {

    }

    public class NoSNINameException extends SNIDispatchException {

    }

    public class UnknownSNINameException extends SNIDispatchException {

    }

}