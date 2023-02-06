/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.List;

public class QuicVersionResult<Report extends TlsScanReport> extends ProbeResult<Report> {

    private List<byte[]> supportedVersions;

    public QuicVersionResult(ProbeType type, List<byte[]> supportedVersions) {
        super(type);
        this.supportedVersions = supportedVersions;
    }

    @Override
    protected void mergeData(Report report) {}

    public List<byte[]> getSupportedVersions() {
        return supportedVersions;
    }
}
