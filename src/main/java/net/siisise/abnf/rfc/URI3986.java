package net.siisise.abnf.rfc;

import java.nio.charset.StandardCharsets;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * URI6874でIPv6の拡張が追加されているのでそちらを推奨する。
 *
 * https://triple-underscore.github.io/rfc-others/RFC3986-ja.html
 *
 * Living Standard ではない
 * https://triple-underscore.github.io/URL-ja.html
 *
 * @see net.siisise.abnf.rfc.URI6874
 */
public class URI3986 {

    public static final ABNFReg REG = new ABNFReg(ABNF5234.BASE, ABNF5234.REG);

    static final ABNF pctEncoded = REG.rule("pct-encoded", ABNF.bin('%').pl(ABNF5234.HEXDIG, ABNF5234.HEXDIG));
    static final ABNF genDelims = REG.rule("gen-delims", ABNF.binlist(":/?#[]@"));
    public static final ABNF subDelims = REG.rule("sub-delims", ABNF.binlist("!$&'()*+,;="));
    public static final ABNF reserved = REG.rule("reserved", genDelims.or1(subDelims));
    public static final ABNF unreserved = REG.rule("unreserved", ABNF5234.ALPHA.or1(ABNF5234.DIGIT, ABNF.list("-._~")));

    static final ABNF scheme = REG.rule("scheme", ABNF5234.ALPHA.pl(ABNF5234.ALPHA.or1(ABNF5234.DIGIT, ABNF.list("+-.")).x()));
    static final ABNF userinfo = REG.rule("userinfo", unreserved.or1(pctEncoded, subDelims, ABNF.bin(':')).x());
    static final ABNF decOctet = REG.rule("dec-octet", "DIGIT "
            + "  / %x31-39 DIGIT "
            + "  / \"1\" 2DIGIT "
            + "  / \"2\" %x30-34 DIGIT "
            + "  / \"25\" %x30-35");
    static final ABNF IPv4address = REG.rule("IPv4address", "dec-octet \".\" dec-octet \".\" dec-octet \".\" dec-octet");
    static final ABNF h16 = REG.rule("h16", ABNF5234.HEXDIG.x(1, 4));
    static final ABNF ls32 = REG.rule("ls32", "( h16 \":\" h16 ) / IPv4address");
    public static final ABNF IPv6address = REG.rule("IPv6address", "6( h16 \":\" ) ls32 "
            + " /                       \"::\" 5( h16 \":\" ) ls32 "
            + " / [               h16 ] \"::\" 4( h16 \":\" ) ls32 "
            + " / [ *1( h16 \":\" ) h16 ] \"::\" 3( h16 \":\" ) ls32 "
            + " / [ *2( h16 \":\" ) h16 ] \"::\" 2( h16 \":\" ) ls32 "
            + " / [ *3( h16 \":\" ) h16 ] \"::\"    h16 \":\"   ls32 "
            + " / [ *4( h16 \":\" ) h16 ] \"::\"              ls32 "
            + " / [ *5( h16 \":\" ) h16 ] \"::\"              h16 "
            + " / [ *6( h16 \":\" ) h16 ] \"::\"");
    static final ABNF IPvFuture = REG.rule("IPvFuture", "\"v\" 1*HEXDIG \".\" 1*( unreserved / sub-delims / \":\" )");
    static final ABNF IPliteral = REG.rule("IP-literal", "\"[\" ( IPv6address / IPvFuture ) \"]\"");
    public static final ABNF regName = REG.rule("reg-name", unreserved.or1(pctEncoded, subDelims).x());
    public static final ABNF host = REG.rule("host", IPliteral.or(IPv4address, regName));
    public static final ABNF port = REG.rule("port", ABNF5234.DIGIT.x());
    public static final ABNF authority = REG.rule("authority", "[ userinfo \"@\" ] host [ \":\" port ]");
    public static final ABNF pchar = REG.rule("pchar", unreserved.or1(pctEncoded,subDelims, ABNF.bin(':'), ABNF.bin('@')));
    public static final ABNF segment = REG.rule("segment", pchar.x());
    public static final ABNF segmentNz = REG.rule("segment-nz", pchar.ix());
    public static final ABNF segmentNzNc = REG.rule("segment-nz-nc", unreserved.or1(pctEncoded,subDelims,ABNF.bin('@')).ix());
    public static final ABNF pathAbempty = REG.rule("path-abempty", ABNF.bin('/').pl(segment).x());
    public static final ABNF pathAbsolute = REG.rule("path-absolute", "\"/\" [ segment-nz *( \"/\" segment ) ]");
    public static final ABNF pathNoscheme = REG.rule("path-noscheme", "segment-nz-nc *( \"/\" segment )");
    static final ABNF pathRootless = REG.rule("path-rootless", "segment-nz *( \"/\" segment )");
    static final ABNF pathEmpty = REG.rule("path-empty", pchar.x(0, 0));
    static final ABNF hierPart = REG.rule("hier-part", ABNF.bin("//").pl(authority, pathAbempty).or( pathAbsolute, pathRootless, pathEmpty));
    static final ABNF path = REG.rule("path", pathAbempty.or(pathAbsolute, pathNoscheme, pathRootless, pathEmpty));
    public static final ABNF query = REG.rule("query", pchar.or1(ABNF.binlist("/?")).x());
    public static final ABNF fragment = REG.rule("fragment", pchar.or1(ABNF.binlist("/?")).x());
    public static final ABNF URI = REG.rule("URI", "scheme \":\" hier-part [ \"?\" query ] [ \"#\" fragment ]");
    // 4.2.
    static final ABNF relativePart = REG.rule("relative-part", ABNF.bin("//").pl( authority, pathAbempty).or(pathAbsolute, pathNoscheme, pathEmpty));
    public static final ABNF relativeRef = REG.rule("relative-ref", relativePart.pl(ABNF.bin('?').pl(query).c(), ABNF.bin('#').pl(fragment).c()));
    public static final ABNF URIreference = REG.rule("URI-reference", URI.or(relativeRef));
    // 4.3.
    static final ABNF absoluteURI = REG.rule("absolute-URI", "scheme \":\" hier-part [ \"?\" query ]");
    
    private final String uri;
    
    public URI3986(String uri) {
        this.uri = uri;
    }

    /**
     * scheme
     * @return scheme 
     */
    public String getScheme() {
        ReadableBlock pac = ReadableBlock.wrap(uri);
        BNF.Match<Packet> m = REG.find(pac, "URI", "scheme");
        Packet s = m.get("scheme").get(0);
        return new String(s.toByteArray(), StandardCharsets.UTF_8);
    }
    
    
    /**
     * RFC 3986 Section 2.x のpercentEncode.
     * https://developer.mozilla.org/ja/docs/Glossary/percent-encoding
     * queryでは使わないっぽい
     * 
     * @param src ふつうの文字列
     * @param bnf エスケープ除外文字判定
     * @return URLに適した文字列
     */
    public static String urlPercentEncode(String src, ABNF bnf) {
        byte[] ar = src.getBytes(StandardCharsets.UTF_8);
        ReadableBlock srcBlock = ReadableBlock.wrap(ar);
        Packet rb = new PacketA();
        
        while ( srcBlock.length() > 0 ) {
            ReadableBlock ur = bnf.is(srcBlock); // utf-8 バイト単位で読めるかな?
            if (ur != null) {
                rb.write(ur);
            } else {
                rb.write('%');
                int c = (byte)srcBlock.read();
                String b = "0" + Integer.toHexString(c).toUpperCase();
                rb.write(b.substring(b.length()-2).getBytes(StandardCharsets.UTF_8));
            }
        }
        return new String(rb.toByteArray(), StandardCharsets.UTF_8);
    }
    
    /**
     * query などにフルエスケープ.
     * @param src 平文
     * @return 符号化文
     */
    public static String unreservedPercentEncode(String src) {
        return urlPercentEncode(src, net.siisise.abnf.rfc.URI3986.unreserved);
    }

    /**
     * 
     */
    static final ABNF queryEscape = net.siisise.abnf.rfc.URI3986.unreserved.or1(ABNF.binlist("!$()*,;:@/"));

    /**
     * queryのkey, valueに使えそうなエスケープ.
     * 
     * @param src key または value
     * @return エスケープされたkey, value
     */
    public static String queryKeyValuePercentEncode(String src) {
        return urlPercentEncode(src, queryEscape);
    }
    
    /**
     * スペースの処理はない.
     * segment など用 /? が含まれない
     * &amp; がエスケープされないかも
     * @param src 平文
     * @return 符号化文
     */
    public static String pcharPercentEncode(String src) {
        return urlPercentEncode(src, net.siisise.abnf.rfc.URI3986.pchar);
    }
    
    /**
     * パラメータのデコード.
     * @param encd 符号化文
     * @return 平文
     */
    public static String urlPercentDecode(String encd) {
        Packet src = new PacketA(encd.getBytes(StandardCharsets.UTF_8));
        Packet dec = new PacketA();
        while (src.size() > 0) {
            byte c = (byte) src.read();
            if (c == '%' && src.length() >= 2) {
                byte[] o = new byte[2];
                src.read(o);
                if (isHex(o[0]) && isHex(o[1])) {
                    c = Byte.parseByte(new String(o, StandardCharsets.UTF_8), 16);
                } else {
                    src.backWrite(o);
                }
            }
            dec.write(new byte[]{c});
        }
        return new String(dec.toByteArray(), StandardCharsets.UTF_8);
    }

    private static boolean isHex(byte c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

}
