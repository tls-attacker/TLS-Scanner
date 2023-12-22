/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.EnumMap;
import java.util.Map;

public class VersionDependentResult<T> implements TestResult {
    protected Map<ProtocolVersion, T> results = new EnumMap<>(ProtocolVersion.class);

    public T getResult(ProtocolVersion version) {
        return results.get(version);
    }

    public void putResult(ProtocolVersion version, T result) {
        results.put(version, result);
    }

    public Map<ProtocolVersion, T> getResultMap() {
        return results;
    }

    @Override
    public String getName() {
        return "<Complex Result>";
    }
}
