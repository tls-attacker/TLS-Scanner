/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

/**
 * Interface defining a configuration filter profile. Implementations provide a set of filter types
 * that can be applied to TLS configurations and a unique identifier for the profile.
 */
public interface ConfigFilterProfile {
    /**
     * Returns the array of configuration filter types that define this profile.
     *
     * @return array of ConfigFilterType enums representing the filters to apply
     */
    public abstract ConfigFilterType[] getConfigFilterTypes();

    /**
     * Returns a unique identifier for this configuration filter profile.
     *
     * @return string identifier for the profile
     */
    public abstract String getIdentifier();
}
