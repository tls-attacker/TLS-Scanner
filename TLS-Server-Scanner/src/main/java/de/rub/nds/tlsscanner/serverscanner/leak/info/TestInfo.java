/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.rub.nds.tlsscanner.serverscanner.leak.info;

/**
 *
 * @author robert
 */
public abstract class TestInfo {

    public abstract String getTechnicalName();

    public abstract String getPrintableName();

    @Override
    public abstract boolean equals(Object o);

    @Override
    public abstract int hashCode();
}
