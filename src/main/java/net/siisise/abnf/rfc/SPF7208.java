package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * @deprecated 未検証あり
 */
@Deprecated
public class SPF7208 {

    public static final ABNFReg REG = new ABNFReg();

    static final ABNF SP = REG.rule("SP", ABNF5234.SP);
    static final ABNF ALPHA = REG.rule("ALPHA", ABNF5234.ALPHA);
    static final ABNF DIGIT = REG.rule("DIGIT", ABNF5234.DIGIT);
    static final ABNF dotAtom = IMF5322.dotAtom;
    static final ABNF quotedString = IMF5322.quotedString;
    static final ABNF comment = IMF5322.comment;
    static final ABNF CFWS = IMF5322.CFWS;
    static final ABNF FWS = IMF5322.FWS;
    static final ABNF CRLF = ABNF5234.CRLF;
    
    // 4.6.1.
    static final ABNF name = REG.rule("name", ALPHA.pl(ALPHA.or(DIGIT,ABNF.bin('-'), ABNF.bin('_'), ABNF.bin('.')).x()));
    // 9.1.
    static final ABNF key = REG.rule("key", "\"client-ip\" / \"envelope-from\" / \"helo\" / \"problem\" / \"receiver\" / \"identity\" / \"mechanism\" / name");
    static final ABNF keyValuePair = REG.rule("key-value-pair", key.pl(CFWS.c(), ABNF.bin('='), dotAtom.or(quotedString)));
    static final ABNF keyValueList = REG.rule("key-value-list", "key-value-pair *( \";\" [CFWS] key-value-pair ) [\";\"]");
    static final ABNF result = REG.rule("result", "\"pass\" / \"fail\" / \"softfail\" / \"neutral\" / \"none\" / \"temperror\" / \"permerror\"" );
    static final ABNF headerField = REG.rule("header-field", ABNF.text("Received-SPF:").pl(CFWS.c(), result, FWS, comment.pl(FWS).c(), keyValueList.c(), CRLF));

    // 7.1.
    static final ABNF delimiter = REG.rule("delimiter","\".\" / \"-\" / \"+\" / \",\" / \"/\" / \"_\" / \"=\"");
    static final ABNF transformers = REG.rule("transformers", "DIGIT [ \"r\" ]");
    static final ABNF macroLetter = REG.rule("macro-letter","\"s\" / \"l\" / \"o\" / \"d\" / \"i\" / \"p\" / \"h\" / \"c\" / \"r\" / \"t\" / \"v\"");
    static final ABNF macroLiteral = REG.rule("macro-literal", "%x21-24 / %x26-7E");
    static final ABNF macroExpand = REG.rule("macro-expand", "( \"%{\" macro-letter transformers *delimiter \"}\" ) / \"%%\" / \"%_\" / \"%-\"");
    static final ABNF macroString = REG.rule("macro-string", macroExpand.or(macroLiteral).x());
    static final ABNF explainString = REG.rule("explain-string", macroString.or(SP).x());
    static final ABNF alphanum = REG.rule("alphanum", ABNF5234.ALPHA.or(ABNF5234.DIGIT));
    static final ABNF toplabel = REG.rule("toplabel", "( *alphanum ALPHA *alphanum ) / ( 1*alphanum \"-\" *( alphanum / \"-\" ) alphanum )"); // ToDo: 要検証
    static final ABNF domainEnd = REG.rule("domain-end", "( \".\" toplabel [ \".\" ] ) / macro-expand");
    static final ABNF domainSpec = REG.rule("domain-spec", macroString.pl(domainEnd)); // まだ
    // 6.2.
    static final ABNF explanation = REG.rule("explanation", ABNF.text("exp").pl(ABNF.bin('='), domainSpec));
    // 6.1.
    static final ABNF redirect = REG.rule("redirect", ABNF.text("redirect").pl(ABNF.bin('='), domainSpec));
    // 5.7.
    static final ABNF exists = REG.rule("exists", ABNF.text("exists").pl(ABNF.bin(':'), domainSpec));
    // 5.6. "ip4" and "ip6"
    static final ABNF ip6Network = REG.rule("ipv6-network", IPv64291.IPv6address); // Section 2.2 of [RFC 4291]
    static final ABNF qnum = REG.rule("qnum", ABNF5234.DIGIT.or(
            ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT),
            ABNF.bin('1').pl(ABNF5234.DIGIT.x(2, 2)),
            ABNF.bin('2').pl(ABNF.range(0x30, 0x34), ABNF5234.DIGIT),
            ABNF.text("25").pl(ABNF.range(0x30, 0x35))));
    static final ABNF ip4Network = REG.rule("ip4-network", qnum.pl(ABNF.bin('.'), qnum, ABNF.bin('.'), qnum, ABNF.bin('.'), qnum));
    static final ABNF ip6CidrLength = REG.rule("ip6-cidr-length", ABNF.bin('/').pl(ABNF.bin('0').or(ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT.x(0, 2)))));
    static final ABNF ip4CidrLength = REG.rule("ip4-cidr-length", ABNF.bin('/').pl(ABNF.bin('0').or(ABNF.range(0x31, 0x39).pl(ABNF5234.DIGIT.x(0, 1)))));
    static final ABNF dualCidrLength = REG.rule("dual-cidr-length", ip4CidrLength.c().pl(ABNF.bin('/').pl(ip6CidrLength).c()));
    static final ABNF ip6 = REG.rule("ip6", ABNF.text("ip6").pl(ABNF.bin(':'), ip6Network, ip6CidrLength.c()));
    static final ABNF ip4 = REG.rule("ip4", ABNF.text("ip4").pl(ABNF.bin(':'), ip4Network, ip4CidrLength.c()));
    // 5.5. (do not use)
    static final ABNF ptr = REG.rule("ptr", ABNF.text("ptr").pl(ABNF.bin(':').pl(domainSpec).c()));
    // 5.4.
    static final ABNF mx = REG.rule("mx", ABNF.text("mx").pl(ABNF.bin(':').pl(domainSpec).c(), dualCidrLength.c()));
    // 5.3.
    static final ABNF a = REG.rule("a", ABNF.text("a").pl(ABNF.bin(':').pl(domainSpec).c(), dualCidrLength.c()));
    // 5.2.
    static final ABNF include = REG.rule("include", ABNF.text("include").pl(ABNF.bin(':'), domainSpec));
    // 5.1.
    static final ABNF all = REG.rule("all", ABNF.text("all"));
    //
    // 4.6.1
    // 6.
    static final ABNF unknownModifier = REG.rule("unknown-modifier", name.pl(ABNF.bin('='),macroString));
    static final ABNF modifier = REG.rule("modifier",redirect.or(explanation,unknownModifier));
    static final ABNF mechanism = REG.rule("mechanism",all.or(include,a,mx,ptr,ip4,ip6,exists));
    static final ABNF qualifier = REG.rule("qualifier", ABNF.list("+-?~"));
    static final ABNF directive = REG.rule("directive", qualifier.c().pl(mechanism));
    static final ABNF terms = REG.rule("terms", SP.ix().pl(directive.or(modifier)).x());
    // 4.5.
    static final ABNF version = REG.rule("version", ABNF.text("v=spf1"));
    public static final ABNF record = REG.rule("record", version.pl(terms, SP.x()));
}
