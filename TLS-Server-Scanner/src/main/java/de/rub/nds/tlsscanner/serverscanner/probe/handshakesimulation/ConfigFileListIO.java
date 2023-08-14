/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

import de.rub.nds.scanner.core.util.JaxbSerializer;
import jakarta.xml.bind.JAXBException;
import java.util.Set;

public class ConfigFileListIO extends JaxbSerializer<ConfigFileList> {

    public ConfigFileListIO() throws JAXBException {
        super(Set.of(ConfigFileListIO.class));
    }
}
