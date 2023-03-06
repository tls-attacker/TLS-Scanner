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

    public QuicTls12HandshakeResult(boolean handshakeCompleted, ConnectionCloseFrame connectionCloseFrame) {
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
