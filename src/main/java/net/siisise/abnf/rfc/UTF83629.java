package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 * RFC 3629 UTF-8, a transformation format of ISO 10646.
 * 4. Syntax of UTF-8 Byte Sequences
 * 
 */
public class UTF83629 {

    public static ABNFReg REG = new ABNFReg();

    static ABNF UTF8tail = REG.rule("UTF8-tail", ABNF.range(0x80, 0xBF));
    static ABNF UTF81 = REG.rule("UTF8-1", ABNF.range(0, 0x7f));
    static ABNF UTF82 = REG.rule("UTF8-2", "%xC2-DF UTF8-tail");
    static ABNF UTF83 = REG.rule("UTF8-3", "%xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) / %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )");
    static ABNF UTF84 = REG.rule("UTF8-4", "%xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) / %xF4 %x80-8F 2( UTF8-tail )");
    public static ABNF UTF8char = REG.rule("UTF8-char", UTF81.or(UTF82, UTF83, UTF84));
    public static ABNF UTF8octets = REG.rule("UTF8-octets", UTF8char.x());
}
