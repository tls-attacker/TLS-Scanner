/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.invalidCurve;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class InvalidCurveParameterSet {
    private ProtocolVersion protocolVersion;
    private List<CipherSuite> cipherSuites;
    private NamedGroup namedGroup;
    private ECPointFormat pointFormat;
    private boolean twistAttack;
    
    public InvalidCurveParameterSet(ProtocolVersion protocolVersion, List<CipherSuite> cipherSuites, NamedGroup namedGroup, ECPointFormat pointFormat, boolean twistAttack)
    {
        this.protocolVersion = protocolVersion;
        this.cipherSuites = cipherSuites;
        this.namedGroup = namedGroup;
        this.pointFormat = pointFormat;
        this.twistAttack = twistAttack;
    }
    public InvalidCurveParameterSet(ProtocolVersion protocolVersion, CipherSuite cipherSuite, NamedGroup namedGroup, ECPointFormat pointFormat, boolean twistAttack)
    {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(cipherSuite);
        
        this.protocolVersion = protocolVersion;
        this.cipherSuites = cipherSuites;
        this.namedGroup = namedGroup;
        this.pointFormat = pointFormat;
        this.twistAttack = twistAttack;
    }

    /**
     * @return the protocolVersion
     */
    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * @return the cipherSuites
     */
    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    /**
     * @return the namedGroup
     */
    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    /**
     * @return the pointFormats
     */
    public ECPointFormat getPointFormat() {
        return pointFormat;
    }

    /**
     * @return the twistAttack
     */
    public boolean isTwistAttack() {
        return twistAttack;
    }
    
    @Override
    public String toString(){
        String parameter = ">";
        for(CipherSuite cipherSuite: cipherSuites)
        {
            parameter = parameter + cipherSuite.toString();
        }
        
        parameter = protocolVersion.toString() + ">" + namedGroup.toString() + ">" + pointFormat.toString() + parameter + (twistAttack?">CurveTwist":"");
        return parameter;
    }
}
