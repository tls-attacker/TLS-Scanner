/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class InvalidCurveVector implements Vector {

    private ProtocolVersion protocolVersion;
    private CipherSuite cipherSuite;
    private NamedGroup namedGroup;
    private ECPointFormat pointFormat;
    private boolean twistAttack;
    private boolean attackInRenegotiation;
    private List<NamedGroup> ecdsaRequiredGroups;

    private InvalidCurveVector() {
    }

    public InvalidCurveVector(ProtocolVersion protocolVersion, CipherSuite cipherSuite, NamedGroup namedGroup,
        ECPointFormat pointFormat, boolean twistAttack, boolean attackInRenegotiation,
        List<NamedGroup> ecdsaRequiredGroups) {

        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.namedGroup = namedGroup;
        this.pointFormat = pointFormat;
        this.twistAttack = twistAttack;
        this.attackInRenegotiation = attackInRenegotiation;
        this.ecdsaRequiredGroups = ecdsaRequiredGroups;
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
    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public List<CipherSuite> getCipherSuiteAsList() {
        List<CipherSuite> cipherList = new LinkedList<>();
        cipherList.add(cipherSuite);

        return cipherList;
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
    public String toString() {
        String parameter = ">";
        parameter = parameter + cipherSuite.toString();

        parameter = protocolVersion.toString() + ">" + namedGroup.toString() + ">"
            + (attackInRenegotiation ? "Renegotiation>" : "") + pointFormat.toString() + parameter
            + (twistAttack ? ">CurveTwist" : "");
        return parameter;
    }

    /**
     * @return the attackInRenegotiation
     */
    public boolean isAttackInRenegotiation() {
        return attackInRenegotiation;
    }

    /**
     * @param attackInRenegotiation
     *                              the attackInRenegotiation to set
     */
    public void setAttackInRenegotiation(boolean attackInRenegotiation) {
        this.attackInRenegotiation = attackInRenegotiation;
    }

    @Override
    public String getName() {
        return toString();
    }

    public List<NamedGroup> getEcdsaRequiredGroups() {
        return ecdsaRequiredGroups;
    }

    public boolean equals(InvalidCurveVector toCompare) {
        if (protocolVersion != toCompare.getProtocolVersion() || cipherSuite != toCompare.getCipherSuite()
            || namedGroup != toCompare.getNamedGroup() || pointFormat != toCompare.getPointFormat()
            || twistAttack != toCompare.isTwistAttack() || attackInRenegotiation != toCompare.isAttackInRenegotiation()
            || !ecdsaRequiredGroups.equals(toCompare.getEcdsaRequiredGroups())) {
            return false;
        }

        return true;
    }

    public void setEcdsaRequiredGroups(List<NamedGroup> ecdsaRequiredGroups) {
        this.ecdsaRequiredGroups = ecdsaRequiredGroups;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }
}
