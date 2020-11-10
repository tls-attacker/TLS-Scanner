/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;

public interface ClientAdapter {
    public ClientInfo getReportInformation();

    public void prepare(boolean clean);

    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException;

    public void cleanup(boolean deleteAll);

}