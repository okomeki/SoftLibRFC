package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 *
 */
public class IPv64291 {
    public static final ABNFReg REG = new ABNFReg();    
//    static ABNF ipv6Network = REG.rule("ipv6-network", IPv62373.IPv6address);
    // Section 2.2.
    static ABNF IPv6address = REG.rule("ipv6-address", URI3986.IPv6address);
}
