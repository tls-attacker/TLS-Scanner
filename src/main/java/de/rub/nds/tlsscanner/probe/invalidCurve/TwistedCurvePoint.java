/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 */
package de.rub.nds.tlsscanner.probe.invalidCurve;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
public enum TwistedCurvePoint {
    SECP224R1Twist(new BigInteger("17106989127857552855725756953356110673539678264821831145985802754995"), new BigInteger("2566101124365632397844458605929357536180013896200508088177876323735"), new BigInteger("11"), NamedGroup.SECP224R1, new BigInteger("3175864818384803226284209479105748741528094761311898051280852688807")),
    SECP256R1Twist(new BigInteger("11296743249963978181704241704878532502264637199842491733577816400178327043224"), new BigInteger("38905571554606584565094822019184577057748774168446697917324971282029240447595"), new BigInteger("5"), NamedGroup.SECP256R1, new BigInteger("76201252277444234128031997593924834580542434278281275491282786284156293877336"));

    
    private BigInteger publicPointBaseX;
    
    //Only used to fill bytes when no compression is used - Y coordinate is not needed for the attack
    private BigInteger publicPointBaseY;
    
    //The value we are using to get a twisted curve
    //d*y^2 = x^3 + ax + b
    private BigInteger d;
    
    //The intended group (curve without twist)
    private NamedGroup intendedNamedGroup;
    private BigInteger order;
    
    private TwistedCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order, NamedGroup intendedNamedGroup, BigInteger d)
    {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.intendedNamedGroup = intendedNamedGroup;
        this.d = d;
    } 

    /**
     * @return the d
     */
    public BigInteger getD() {
        return d;
    }

    /**
     * @param d the d to set
     */
    public void setD(BigInteger d) {
        this.d = d;
    }

    /**
     * @return the publicPointBaseX
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX the publicPointBaseX to set
     */
    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    /**
     * @return the publicPointBaseY
     */
    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    /**
     * @param publicPointBaseY the publicPointBaseY to set
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @return the intendedNamedGroup
     */
    public NamedGroup getIntendedNamedGroup() {
        return intendedNamedGroup;
    }

    /**
     * @param intendedNamedGroup the intendedNamedGroup to set
     */
    public void setIntendedNamedGroup(NamedGroup intendedNamedGroup) {
        this.intendedNamedGroup = intendedNamedGroup;
    }

    /**
     * @return the order
     */
    public BigInteger getOrder() {
        return order;
    }

    /**
     * @param order the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }
    
    public static TwistedCurvePoint fromIntendedNamedGroup(NamedGroup group)
    {
        for(TwistedCurvePoint point : values())
        {
            if(point.getIntendedNamedGroup() == group)
            {
                return point;
            }
        }
        return null;
    }
}
