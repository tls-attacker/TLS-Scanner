/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class DebugExtensionDelegateTest {

    private Config mockConfig;
    private DebugExtensionDelegate delegate;

    @Before
    public void setUp() {
        mockConfig = Mockito.mock(Config.class);
        delegate = new DebugExtensionDelegate();
    }

    @Test
    public void testApplyDelegate_whenEnabled_shouldAddDebugExtension()
            throws ConfigurationException {
        delegate.setDebugExtension(true);
        delegate.applyDelegate(mockConfig);
        Mockito.verify(mockConfig).setAddDebugExtension(true);
    }

    @Test
    public void testApplyDelegate_whenDisabled_shouldNotAddDebugExtension()
            throws ConfigurationException {
        delegate.setDebugExtension(false);
        delegate.applyDelegate(mockConfig);
        Mockito.verify(mockConfig, Mockito.never()).setAddDebugExtension(true);
    }
}
