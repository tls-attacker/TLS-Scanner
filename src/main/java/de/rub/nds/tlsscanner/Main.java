/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Main {
    public static void main(String[] args)
    {
        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        commander.parse(args);
    }
}
