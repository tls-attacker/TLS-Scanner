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
import static de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurvePoint.values;
import java.math.BigInteger;

/**
 *
 */
public enum InvalidCurvePoint {
  
    SECP160K1(new BigInteger("425552458851840941481027496383389644696569727561"), new BigInteger("11485143142956209199142378770087256671381298159"), new BigInteger("5"), NamedGroup.SECP160K1),
    SECP160R1(new BigInteger("70737555688374993220247787883861560922043479800"), new BigInteger("619890523255902931491123955019622585173218236393"), new BigInteger("5"), NamedGroup.SECP160R1),
    SECP160R2(new BigInteger("863862247631971056860551604588520891633553550623"), new BigInteger("340259250818995598482185592824174471282682081636"), new BigInteger("5"), NamedGroup.SECP160R2),
    SECP192K1(new BigInteger("5814372642690793436265440673914195440014923478054929205070"), new BigInteger("105181686485035786562618505860267025965530014527222640388"), new BigInteger("7"), NamedGroup.SECP192K1),
    SECP192R1(new BigInteger("5754814103567565617817847103463830311362431143258274644776"), new BigInteger("3873867630694792478989881124754811112711867268763434108316"), new BigInteger("5"), NamedGroup.SECP192R1),
    SECP224K1(new BigInteger("19426728020833515942727768972560011774233277858254723645333108289308"), new BigInteger("28673861406384377595532480195053726013228968274754852158234985060"), new BigInteger("7"), NamedGroup.SECP224K1),
    SECP224R1(new BigInteger("21318454105160239136008676843023708345048831524844918858544830829860"), new BigInteger("11817798202927796291211463376417710597529081672180127478813242496708"), new BigInteger("5"), NamedGroup.SECP224R1),
    SECP256K1(new BigInteger("95553118718241106927847770595627065024382514656196684618171092635254172656338"), new BigInteger("85264534900992313617268082135748672359172206499910729239553951103965124704495"), new BigInteger("7"), NamedGroup.SECP256K1),
    SECP256R1(new BigInteger("31332110690492187445260495663208743947792732563591899213372296327611402121926"), new BigInteger("12139807749705329982622931683970472905802896853101847580492258710762645305286"), new BigInteger("5"), NamedGroup.SECP256R1),
    SECP384R1(new BigInteger("39348173778840561204685074847844151047779998913643881137854433861527572697315209734149603412183866217077663711979693"), new BigInteger("36932512539757920398968132621902702222594266109104578531574507817918455956230201066237340715233511335004515367212714"), new BigInteger("5"), NamedGroup.SECP384R1),
    SECP521R1(new BigInteger("2405291753046500187134120628745370137255675375121937462218028282674723179863631594473989830570165114274954776318927055277180282175388127735437979130491837584"), new BigInteger("4424519299442724028232009248280188421579335414561161283698411468130623060333270200383553413666364060452116476165446784931779226984844187888124157670027854238"), new BigInteger("5"), NamedGroup.SECP521R1),
    BRAINPOOLP256R1(new BigInteger("25571266623996642126642115696232646087234824833987489459536396710951884773437"), new BigInteger("60113698667221334592627780253697066645500490287596090324646717788550908961405"), new BigInteger("5"), NamedGroup.BRAINPOOLP256R1),
    BRAINPOOLP384R1(new BigInteger("20662298615180124307621335639003967111203848106284232559676146137313455990089734910063208996488101281832777419043208"), new BigInteger("19746590747011010994144150719803230605919028806632153777333454613343223547666948778676516429168394533004893493248990"), new BigInteger("5"), NamedGroup.BRAINPOOLP384R1),
    BRAINPOOLP512R1(new BigInteger("829763080174561762606114938433082993146041653634191705996267204133374687912661308895015236997065818666803079974704469504063753865521081857821907856386513"), new BigInteger("821197154271176016882204638258702323075102662909087319211703053248569138152566562386580502231846025420145393572780195844698396431105413115893869247316496"), new BigInteger("5"), NamedGroup.BRAINPOOLP512R1);
    
    private BigInteger publicPointBaseX;
    private BigInteger publicPointBaseY;
    private final NamedGroup namedGroup;
    private BigInteger order;
    
    private InvalidCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order, NamedGroup namedGroup)
    {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.namedGroup = namedGroup;
    }
    
    public static InvalidCurvePoint fromNamedGroup(NamedGroup group)
    {
        for(InvalidCurvePoint point : values())
        {
            if(point.getNamedGroup() == group)
            {
                return point;
            }
        }
        return null;
    }
    
    public  NamedGroup getNamedGroup()
    {
        return namedGroup;
    }
    
    public BigInteger getOrder()
    {
        return order;
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
     * @param order the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }
               
}
