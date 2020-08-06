package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SNIDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) {
        ServerNameIndicationExtensionMessage SNI = null;
        for (ExtensionMessage ext : dispatchInformation.chlo.getExtensions()) {
            if (ext instanceof ServerNameIndicationExtensionMessage) {
                SNI = (ServerNameIndicationExtensionMessage) ext;
                break;
            }
        }
        String name = null;
        for (ServerNamePair snp : SNI.getServerNameList()) {
            if (snp.getServerNameType().getValue() == 0) {
                name = new String(snp.getServerName().getValue());
            } else {
                LOGGER.warn("Received unknown SNI Name Type {}", snp.getServerNameType().getValue());
            }
        }
        LOGGER.debug("Got '{}'", name);
        if (name == null) {
            // TODO error handling
        }
        return null;
    }

}