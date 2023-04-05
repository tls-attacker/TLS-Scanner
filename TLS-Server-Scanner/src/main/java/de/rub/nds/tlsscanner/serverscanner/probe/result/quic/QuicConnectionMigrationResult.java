/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.quic;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class QuicConnectionMigrationResult extends ProbeResult<ServerReport> {

    private boolean portConnectionMigrationSuccessful;
    private String ipv6Address;
    private boolean ipv6HandshakeSuccessful;
    private boolean ipv6ConnectionMigrationSuccessful;

    public QuicConnectionMigrationResult() {
        super(QuicProbeType.CONNECTION_MIGRATION);
    }

    public QuicConnectionMigrationResult(
            boolean portConnectionMigrationSuccessful,
            String ipv6Address,
            boolean ipv6HandshakeSuccessful,
            boolean ipv6ConnectionMigrationSuccessful) {
        this();
        this.portConnectionMigrationSuccessful = portConnectionMigrationSuccessful;
        this.ipv6Address = ipv6Address;
        this.ipv6HandshakeSuccessful = ipv6HandshakeSuccessful;
        this.ipv6ConnectionMigrationSuccessful = ipv6ConnectionMigrationSuccessful;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setQuicConnectionMigrationResult(this);
    }

    public boolean isPortConnectionMigrationSuccessful() {
        return portConnectionMigrationSuccessful;
    }

    public void setPortConnectionMigrationSuccessful(boolean portConnectionMigrationSuccessful) {
        this.portConnectionMigrationSuccessful = portConnectionMigrationSuccessful;
    }

    public String getIpv6Address() {
        return ipv6Address;
    }

    public void setIpv6Address(String ipv6Address) {
        this.ipv6Address = ipv6Address;
    }

    public boolean isIpv6HandshakeSuccessful() {
        return ipv6HandshakeSuccessful;
    }

    public void setIpv6HandshakeSuccessful(boolean ipv6HandshakeSuccessful) {
        this.ipv6HandshakeSuccessful = ipv6HandshakeSuccessful;
    }

    public boolean isIpv6ConnectionMigrationSuccessful() {
        return ipv6ConnectionMigrationSuccessful;
    }

    public void setIpv6ConnectionMigrationSuccessful(boolean ipv6ConnectionMigrationSuccessful) {
        this.ipv6ConnectionMigrationSuccessful = ipv6ConnectionMigrationSuccessful;
    }
}
