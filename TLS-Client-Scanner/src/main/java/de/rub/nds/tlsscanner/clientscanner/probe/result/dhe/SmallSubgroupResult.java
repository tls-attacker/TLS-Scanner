/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result.dhe;

import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.tlsscanner.clientscanner.constants.SmallSubgroupType;

public class SmallSubgroupResult {

    private final TestResult result;
    private final SmallSubgroupType type;

    public SmallSubgroupResult(TestResult result, SmallSubgroupType type) {
        this.result = result;
        this.type = type;
    }

    public TestResult getResult() {
        return result;
    }

    public SmallSubgroupType getType() {
        return type;
    }
}
