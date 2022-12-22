package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 * JavaのURI相当.
 * RFC 2396 + RFC 2732 Format for Literal IPv6 Addresses in URL's
 */
public class URI2732 {

    static final ABNFReg REG = new ABNFReg(URI2396.REG);

    static final ABNF IPv6address = REG.rule("IPv6address", IPv62373.IPv6address);
    static final ABNF IPv6reference = REG.rule("ipv6reference", ABNF.bin('[').pl(IPv6address, ABNF.bin(']')));
    static final ABNF host = REG.rule("host", URI2396.hostname.or(URI2396.IPv4address, IPv6reference));
    static final ABNF reserved = REG.rule("reserved", ABNF.binlist(";/?:@&=+$,[]"));
    static final ABNF unwise = REG.rule("unwise", ABNF.binlist("{}|\\^`"));
}
