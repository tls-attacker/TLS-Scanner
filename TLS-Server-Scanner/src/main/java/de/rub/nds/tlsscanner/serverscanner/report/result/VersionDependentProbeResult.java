/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import java.util.EnumMap;
import java.util.Map;
import java.util.Map.Entry;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public abstract class VersionDependentProbeResult<T extends VersionDependentResult> extends ProbeResult {
    private final Map<ProtocolVersion, T> results = new EnumMap<>(ProtocolVersion.class);

    public VersionDependentProbeResult(ProbeType type) {
        super(type);
    }

    public void putResult(T result) {
        results.put(result.getProtocolVersion(), result);
    }

    public T getResult(ProtocolVersion protocolVersion) {
        return results.get(protocolVersion);
    }

    public Map<ProtocolVersion, T> getResultMap() {
        return results;
    }

    @Override
    protected void mergeData(SiteReport report) {
        for (Entry<ProtocolVersion, T> entry : results.entrySet()) {
            assert entry.getKey() == entry.getValue().getProtocolVersion();
            entry.getValue().writeToSiteReport(report);
        }
    }

}
