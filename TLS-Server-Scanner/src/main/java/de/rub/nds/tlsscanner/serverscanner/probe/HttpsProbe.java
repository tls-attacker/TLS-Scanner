/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;

public abstract class HttpsProbe extends TlsProbe {

    public HttpsProbe(ParallelExecutor parallelExecutor, ProbeType type, ScannerConfig scannerConfig) {
        super(parallelExecutor, type, scannerConfig);
    }

    protected HttpsRequestMessage getHttpsRequest() {
        HttpsRequestMessage httpsRequestMessage = new HttpsRequestMessage();
        httpsRequestMessage.setRequestPath("/");

        httpsRequestMessage.getHeader().add(new HostHeader());
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader("Connection", "keep-alive"));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader("Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"));
        httpsRequestMessage.getHeader()
            .add(new GenericHttpsHeader("Accept-Encoding", "compress, deflate, exi, gzip, br, bzip2, lzma, xz"));
        httpsRequestMessage.getHeader()
            .add(new GenericHttpsHeader("Accept-Language", "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader("Upgrade-Insecure-Requests", "1"));
        httpsRequestMessage.getHeader().add(new GenericHttpsHeader("User-Agent",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3449.0 Safari/537.36"));
        return httpsRequestMessage;
    }
}
