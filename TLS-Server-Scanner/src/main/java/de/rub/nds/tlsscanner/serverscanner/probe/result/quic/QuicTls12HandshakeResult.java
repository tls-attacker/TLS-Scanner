/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.quic;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class QuicTls12HandshakeResult extends ProbeResult<ServerReport> {

    private boolean handshakeCompleted;
    private ConnectionCloseFrame connectionCloseFrame;

    public QuicTls12HandshakeResult() {
        super(QuicProbeType.TLS12_HANDSHAKE);
    }

    public QuicTls12HandshakeResult(boolean handshakeCompleted) {
        this();
        this.handshakeCompleted = handshakeCompleted;
    }

    public QuicTls12HandshakeResult(
            boolean handshakeCompleted, ConnectionCloseFrame connectionCloseFrame) {
        this();
        this.handshakeCompleted = handshakeCompleted;
        this.connectionCloseFrame = connectionCloseFrame;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setQuicTls12HandshakeResult(this);
    }

    public boolean isHandshakeCompleted() {
        return handshakeCompleted;
    }

    public ConnectionCloseFrame getConnectionCloseFrame() {
        return connectionCloseFrame;
    }
}
