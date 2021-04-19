package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * SIP用.
 * Updates: 3261
 *
 * @see IPv62373
 */
public class IPv65954 {

    static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    public static final ABNF IPv6reference = REG.rule("IPv6reference", ABNF.text("[").pl(URI3986.IPv6address, ABNF.text(']')));
}
