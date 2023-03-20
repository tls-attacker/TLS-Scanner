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
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;
import java.util.stream.Collectors;

public class QuicVersionResult extends ProbeResult<ServerReport> {

    private final List<byte[]> supportedVersions;

    public QuicVersionResult(List<byte[]> supportedVersions) {
        super(QuicProbeType.SUPPORTED_VERSION);
        this.supportedVersions = supportedVersions;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setSupportedQuicVersions(
                supportedVersions.stream()
                        .map(
                                versionBytes ->
                                        new Entry(
                                                QuicVersion.getVersionNameFromBytes(versionBytes),
                                                versionBytes))
                        .collect(Collectors.toList()));
    }

    public List<byte[]> getSupportedVersions() {
        return supportedVersions;
    }

    public class Entry {
        private String versionName;
        private byte[] versionBytes;

        public Entry(String versionName, byte[] versionBytes) {
            this.versionName = versionName;
            this.versionBytes = versionBytes;
        }

        public String getVersionName() {
            return versionName;
        }

        public void setVersionName(String versionName) {
            this.versionName = versionName;
        }

        public byte[] getVersionBytes() {
            return versionBytes;
        }

        public void setVersionBytes(byte[] versionBytes) {
            this.versionBytes = versionBytes;
        }
    }
}
