/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.connectivity;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class ConnectivityChecker {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Connection connection;

    public ConnectivityChecker(Connection connection) {
        this.connection = connection;
        if (connection instanceof AliasedConnection) {
            ((AliasedConnection) connection).normalize((AliasedConnection) connection);
        }
    }

    public boolean isConnectable() {
        if (connection.getTransportHandlerType() == null) {
            connection.setTransportHandlerType(TransportHandlerType.TCP);
        }
        if (connection.getTimeout() == null) {
            connection.setTimeout(5000);
        }
        TransportHandler handler = TransportHandlerFactory.createTransportHandler(connection);
        try {
            handler.initialize();
        } catch (IOException ex) {
            LOGGER.debug(ex);
            return false;
        }
        if (handler.isInitialized()) {
            try {
                handler.closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
            return true;
        } else {
            return false;
        }
    }
}
