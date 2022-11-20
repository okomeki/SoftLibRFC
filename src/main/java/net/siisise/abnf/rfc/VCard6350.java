package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 *
 */
public class VCard6350 {
    public static ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    
//    static ABNF text = REG.rule("text",TEXT_CHAR.x());
    static ABNF value = REG.rule("value","text / text-list / date-list / time-list / date-time-list / date-and-or-time-list / timestamp-list / boolean / integer-list / float-list / URI / utc-offset / Language-Tag / iana-valuespec");

    
    static ABNF group = REG.rule("group","1*(ALPHA / DIGIT / \"-\")");
    static ABNF contentline = REG.rule("contentline","[group \".\"] name *(\";\" param) \":\" value CRLF");
    public static ABNF vcard = REG.rule("\"BEGIN:VCARD\" CRLF \"VERSION:4.0\" CRLF 1*contentline \"END:VCARD\" CRLF");
    public static ABNF vcardEntry = REG.rule("vcard-entry", vcard.ix());
}
