package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * UUIDのABNF.
 * 
 * @see https://tools.ietf.org/html/rfc4122
 */
public class UUID4122 {
    public static ABNFReg REG = new ABNFReg();

    static ABNF hexDigit = REG.rule("hexDigit", ABNF5234.HEXDIG);
    static ABNF hexOctet = REG.rule("hexOctet", hexDigit.x(2,2));
    static ABNF timeLow = REG.rule("time-low",hexOctet.x(4,4));
    static ABNF timeMid = REG.rule("time-mid",hexOctet.x(2,2));
    static ABNF timeHighAndVersion = REG.rule("time-high-and-version",hexOctet.x(2,2));
    static ABNF clockSeqAndReserved = REG.rule("clock-seq-and-reserved",hexOctet);
    static ABNF clockSeqLow = REG.rule("clock-seq-low", hexOctet);
    static ABNF node = REG.rule("node", hexOctet.x(6,6));
    public static ABNF UUID = timeLow.pl(ABNF.bin('-'),timeMid,ABNF.bin('-'),timeHighAndVersion,ABNF.bin('-'),clockSeqAndReserved,clockSeqLow,ABNF.bin('-'),node);

    public static String NilUUID =  "00000000-0000-0000-0000-000000000000";
}
