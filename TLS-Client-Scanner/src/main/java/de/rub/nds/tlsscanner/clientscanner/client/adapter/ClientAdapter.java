/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;

public interface ClientAdapter {

    public void prepare();

    public ClientInfo getReportInformation();

    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException;

    public void cleanup();

}