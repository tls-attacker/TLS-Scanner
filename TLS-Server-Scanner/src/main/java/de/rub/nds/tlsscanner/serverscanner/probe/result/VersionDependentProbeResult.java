/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.EnumMap;
import java.util.Map;
import java.util.Map.Entry;

public abstract class VersionDependentProbeResult<T extends VersionDependentResult>
        extends ProbeResult<ServerReport> {
    private final Map<ProtocolVersion, T> results = new EnumMap<>(ProtocolVersion.class);

    protected VersionDependentProbeResult(ProbeType type) {
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
    protected void mergeData(ServerReport report) {
        for (Entry<ProtocolVersion, T> entry : results.entrySet()) {
            assert entry.getKey() == entry.getValue().getProtocolVersion();
            entry.getValue().writeToServerReport(report);
        }
    }
}
