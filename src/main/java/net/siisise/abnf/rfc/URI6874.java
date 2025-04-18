package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 * RFC 3986 のIP-literal を微修正.
 * IPv6 リンクローカルアドレス の ZoneIDに対応したもの
 */
public class URI6874 extends URI3986 {

    public static final ABNFReg REG = new ABNFReg(URI3986.REG);

    public static final ABNF ZoneID = REG.rule("ZoneID", "1*( unreserved / pct-encoded )");
    public static final ABNF IPv6addrz = REG.rule("IPv6addrz", "IPv6address \"%25\" ZoneID");
    public static final ABNF IPliteral = REG.rule("IP-literal", "\"[\" ( IPv6address / IPv6addrz / IPvFuture ) \"]\"");

    /**
     * 各定義を使う例
     *
     */
    public static final ABNF URI = REG.href("URI");
    public static final ABNF relativeRef = REG.href("relative-ref");
    public static final ABNF URIreference = REG.href("URI-reference");
    
    public URI6874(String uri) {
        super(uri);
    }
}
