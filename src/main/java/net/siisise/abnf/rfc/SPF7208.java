package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * @deprecated 定義が中途半端
 */
public class SPF7208 {
    public static final ABNFReg REG = new ABNFReg();

    static final ABNF SP = ABNF5234.SP;
    static final ABNF dotAtom = IMF5322.dotAtom;
    static final ABNF quotedString = IMF5322.quotedString;
    static final ABNF comment = IMF5322.comment;
    static final ABNF CFWS = IMF5322.CFWS;
    static final ABNF FWS = IMF5322.FWS;
    static final ABNF CRLF = ABNF5234.CRLF;
//    static final ABNF ip6Network = IPv64291;
    static final ABNF qnum = REG.rule("qnum", ABNF5234.DIGIT.or(
            ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT),
            ABNF.bin('1').pl(ABNF5234.DIGIT),
            ABNF.bin('2').pl(ABNF.range(0x30, 0x34),ABNF5234.DIGIT),
            ABNF.text("25").pl(ABNF.range(0x30, 0x35))));
    static final ABNF ip4Network = REG.rule("ip4-network", qnum.pl(ABNF.bin('.'),qnum,ABNF.bin('.'),qnum,ABNF.bin('.'),qnum));
    static final ABNF ip6CidrLength = REG.rule("ip6-cidr-length", ABNF.bin('/').pl(ABNF.bin('0').or(ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT.x(0,2)))));
    static final ABNF ip4CidrLength = REG.rule("ip4-cidr-length", ABNF.bin('/').pl(ABNF.bin('0').or(ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT.x(0,1)))));
    static final ABNF dualCidrLength = REG.rule("dual-cidr-length", ip4CidrLength.c().pl(ABNF.bin('/').pl(ip6CidrLength).c()));
//    static final ABNF unknownModifier = REG.rule("unknown-modifier", name.pl(ABNF.bin('='),macroString));
//    static final ABNF explanation = REG.rule("explanation", ABNF.text("exp"), ABNF.bin('='), domainSpec);
//    static final ABNF redirect = REG.rule("redirect", ABNF.text("redirect").pl(ABNF.bin('='),domainSpec));
//    static final ABNF modifier = REG.rule("modifier",redirect.or(explanation,unknownModifier));
//    static final ABNF exists = REG.rule("exists",ABNF.text("exists").pl(ABNF.bin(':'),domailSpec));
//    static final ABNF ip6 = REG.rule("ip6",ABNF.text("ip6").pl(ABNF.bin(':'),ip6Network,ip6CidrLength.c()));
    static final ABNF ip4 = REG.rule("ip4",ABNF.text("ip4").pl(ABNF.bin(':'),ip4Network,ip4CidrLength.c()));
//    static final ABNF ptr = REG.rule("ptr", ABNF.text("ptr").pl(ABNF.bin(':').pl(domainSpec).c()));
//    static final ABNF mx = REG.rule("mx", ABNF.text("mx").pl(ABNF.bin(':').pl(domainSpec).c(),dualCidrLength.c()));
//    static final ABNF a = REG.rule("a", ABNF.text("a").pl(ABNF.bin(':').pl(domainSpec).c(),dualCidrLength.c()));
//    static final ABNF include = REG.rule("include",ABNF.text("include").pl(ABNF.bin(':'), domainSpec));
    static final ABNF all = REG.rule("all", ABNF.text("all"));
//    static final ABNF mechanism = REG.rule("mechanism",all.or(include,a,mx,ptr,ip4,ip6,exists));
    static final ABNF qualifier = REG.rule("qualifier", ABNF.list("+-?~"));
//    static final ABNF directive = REG.rule("directive", qualifier.c().pl(mechanism));
//    static final ABNF terms = REG.rule("terms", SP.ix().pl(directive.or(modifier)).x());
    static final ABNF version = REG.rule("version", ABNF.text("v=spf1"));
//    public static final ABNF record = REG.rule("record", version.pl(terms, SP.x()));
}
