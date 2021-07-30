/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.config.modes.scan;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.Subcommand;

public interface ClientAdapterConfig extends Subcommand {
    ClientAdapter createClientAdapter(ClientScannerConfig csConfig);
}
