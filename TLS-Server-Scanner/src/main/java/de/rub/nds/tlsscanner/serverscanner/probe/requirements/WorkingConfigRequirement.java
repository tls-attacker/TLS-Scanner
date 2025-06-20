/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

/** Represents a {@link Requirement} for the requirement of a working config. */
public class WorkingConfigRequirement extends Requirement<ServerReport> {

    private final ConfigSelector configSelector;

    /**
     * Constructs a new WorkingConfigRequirement with the specified ConfigSelector.
     *
     * @param configSelector the ConfigSelector to use for evaluating the requirement
     */
    public WorkingConfigRequirement(ConfigSelector configSelector) {
        this.configSelector = configSelector;
    }

    /**
     * Evaluates whether a working configuration has been found by the ConfigSelector.
     *
     * @param report the ServerReport to evaluate (not used in this implementation)
     * @return true if the ConfigSelector is not null and has found a working configuration, false
     *     otherwise
     */
    @Override
    public boolean evaluate(ServerReport report) {
        if (configSelector == null) {
            return false;
        }
        return configSelector.foundWorkingConfig();
    }

    /**
     * Returns a string representation of this requirement.
     *
     * @return the string "WorkingConfigRequirement"
     */
    @Override
    public String toString() {
        return "WorkingConfigRequirement";
    }
}
