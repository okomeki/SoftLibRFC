package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * RFC 7235 Hypertext Transfer Protocol (HTTP/1.1): Authentication.
 * RFC 7230 の拡張ABNFを使用する
 * http 3の継続仕様は RFC 9110 
 */
public class HTTPAuthentication7235 {

    public static final ABNFReg REG = new ABNFReg(ABNF5234.BASE, HTTP7230.PAR);

    static final ABNF OWS = REG.rule("OWS", HTTP7230.OWS);
    static final ABNF BWS = REG.rule("BWS", HTTP7230.BWS);
    static final ABNF quotedString = REG.rule("quoted-string", HTTP7230.quotedString);
    static final ABNF token = REG.rule("token", HTTP7230.token);

    // token68
    static final ABNF authScheme = REG.rule("auth-scheme", token);
    static final ABNF authParam = REG.rule("auth-param", "token BWS \"=\" BWS ( token / quoted-string )");
    static final ABNF token68 = REG.rule("token68", ABNF5234.ALPHA.or1(ABNF5234.DIGIT, ABNF.binlist("-._~+/")).ix().pl(ABNF.bin('=').x()));
    static final ABNF challenge = REG.rule("challenge","auth-scheme [ 1*SP ( token68 / #auth-param ) ]");
    static final ABNF credentials = REG.rule("credentials","auth-scheme [ 1*SP ( token68 / #auth-param ) ]");
    static final ABNF WWWAuthenticate = REG.rule("WWW-Authenticate","1#challenge");
    static final ABNF authroization = REG.rule("Authorization", credentials);
    static final ABNF proxyAuthenticate = REG.rule("Proxy-Authenticate","1#challenge");
    static final ABNF proxyAuthorization = REG.rule("Proxy-Authorization", credentials);
}
