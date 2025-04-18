package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * toplabel , domainlabel は完全一致判定が必要か
 *
 */
public class URI2396 {

    static final ABNFReg REG = new ABNFReg(ABNF5234.BASE,ABNF5234.REG);

    static final ABNF lowalpha = REG.rule("lowalpha", ABNF.range('a', 'z'));
    static final ABNF upalpha = REG.rule("upalpha", ABNF.range('A', 'Z'));
    static final ABNF alpha = REG.rule("alpha", lowalpha.or1(upalpha)); // ABNF5234.ALPHA
    static final ABNF digit = REG.rule("digit", ABNF5234.DIGIT);
    static final ABNF alphanum = REG.rule("alphanum", alpha.or1(digit));

    static final ABNF reserved = REG.rule("reserved", ABNF.list(";/?:@&=+$,"));  // RFC 2732 で更新
    static final ABNF mark = REG.rule("mark", ABNF.list("-_.!~*'()"));
    public static final ABNF unreserved = REG.rule("unreserved", alphanum.or1(mark));
    static final ABNF hex = REG.rule("hex", digit.or1(ABNF.range('A', 'F'),ABNF.range('a', 'f')));
    static final ABNF escaped = REG.rule("escaped", ABNF.bin('%').pl(hex, hex));
    static final ABNF uric = REG.rule("uric", REG.ref("reserved").or1(unreserved, escaped));
    // 2.4.3. 排除される US-ASCII文字
    static final ABNF control = REG.rule("control", ABNF5234.CTL);
    static final ABNF space = REG.rule("space", ABNF.bin(0x20));
    static final ABNF delims = REG.rule("delims", ABNF.list("<>#%\""));
    public static final ABNF unwise = REG.rule("unwise", ABNF.list("()|\\^[]`")); // RFC 2732 で更新

    static final ABNF query = REG.rule("query", uric.x());
    static final ABNF pchar = REG.rule("pchar", unreserved.or1(escaped, ABNF.list(":@&=+$,")));
    static final ABNF param = REG.rule("param", pchar.x());
    static final ABNF segment = REG.rule("segment", pchar.x().pl(ABNF.bin(';').pl(param).x()));
    static final ABNF pathSegments = REG.rule("path-segments", segment.pl(ABNF.bin('/').pl(segment).x()));
    static final ABNF port = REG.rule("port", digit.x());
    static final ABNF IPv4address = REG.rule("IPv4address", "1*digit \".\" 1*digit \".\" 1*digit \".\" 1*digit");
    /** *(alphanum / XXX ) alphanum が無理なので改変 */
//    static final ABNF toplabel = REG.rule("toplabel", "alpha / alpha *( alphanum / \"-\" ) alphanum");
//    static final ABNF toplabel = REG.rule("toplabel", "alpha *( *( \"-\" ) alphanum )");
    static final ABNF toplabel = REG.rule("toplabel", alpha.pl( ABNF.bin('-').x().pl(alphanum).x()));
    /** *(alphanum / XXX ) alphanum が無理なので改変 */
//    static final ABNF domainlabel = REG.rule("domainlabel", "alphanum / alphanum *( alphanum / \"-\" ) alphanum"); // 元の記述
//    static final ABNF domainlabel = REG.rule("domainlabel", "alphanum *( alphanum / \"-\" ) alphanum / alphanum"); // 一部改変 plmで可能
//    static final ABNF domainlabel = REG.rule("domainlabel",   "alphanum *( *( \"-\" ) alphanum )"); // pl用に改変してみた記述
    static final ABNF domainlabel = REG.rule("domainlabel", alphanum.pl(ABNF.bin('-').x().pl(alphanum).x())); // pl用
    static final ABNF hostname = REG.rule("hostname", "*( domainlabel \".\" ) toplabel [ \".\" ]");
    static final ABNF host = REG.rule("host", hostname.or(IPv4address)); // RFC 2732 で更新
    static final ABNF hostport = REG.rule("hostport", "host [ \":\" port ]");
    static final ABNF userinfo = REG.rule("userinfo", unreserved.or1(escaped, ABNF.binlist(";:&=+$,")));
    static final ABNF server = REG.rule("server", "[ [ userinfo \"@\" ] hostport ]");
    static final ABNF regName = REG.rule("reg-name", unreserved.or1(escaped, ABNF.list("$,;:@&=+")).ix());
    static final ABNF authority = REG.rule("authority", server.or(regName));
    static final ABNF scheme = REG.rule("scheme", "alpha *( alpha / digit / \"+\" / \"-\" / \".\" )");
    static final ABNF uricNoSlash = REG.rule("uric-no-slash", unreserved.or1(escaped, ABNF.binlist(";?:@&=+$,")));
    static final ABNF opaquePart = REG.rule("opaque-part", uricNoSlash.pl(uric.x()));
    static final ABNF absPath = REG.rule("abs-path", ABNF.bin('/').pl(pathSegments));
    static final ABNF path = REG.rule("path", absPath.or(opaquePart).c());
    static final ABNF netPath = REG.rule("net-path", ABNF.bin("//").pl(authority, absPath.c()));
    static final ABNF hierPart = REG.rule("hier-part", netPath.or(absPath).pl(ABNF.bin('?').pl(query).c()));
    public static final ABNF absoluteURI = REG.rule("absoluteURI", scheme.pl(ABNF.bin(':'), hierPart.or(opaquePart)));

    static final ABNF relSegment = REG.rule("rel-segment", unreserved.or(escaped, ABNF.list(";@&=+$,")).ix());
    // 相対パス
    static final ABNF relPath = REG.rule("rel-path", relSegment.pl(absPath.c()));
    static final ABNF relativeURI = REG.rule("relativeURI", "( net-path / abs-path / rel-path ) [ \"?\" query ]");
    static final ABNF fragment = REG.rule("fragment", uric.x());
    // 4. URI参照
    public static final ABNF URIreference = REG.rule("URI-reference", "[ absoluteURI / relativeURI ] [ \"#\" fragment ]");
}
