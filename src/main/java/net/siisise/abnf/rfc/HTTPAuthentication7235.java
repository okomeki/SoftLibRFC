package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 *
 */
public class HTTPAuthentication7235 {

    public static ABNFReg REG = new ABNFReg(ABNF5234.BASE, HTTP7230.PAR);

    static ABNF OWS = REG.rule("OWS", HTTP7230.OWS);
    static ABNF BWS = REG.rule("BWS", HTTP7230.BWS);
    static ABNF quotedString = REG.rule("quoted-string", HTTP7230.quotedString);
    static ABNF token = REG.rule("token", HTTP7230.token);

    static ABNF authScheme = REG.rule("auth-scheme", token);
    static ABNF authParam = REG.rule("auth-param", "token BWS \"=\" BWS ( token / quoted-string )");
    static ABNF token68 = REG.rule("token68", "1*( ALPHA / DIGIT /"
            + " \"-\" / \".\" / \"_\" / \"~\" / \"+\" / \"/\" ) *\"=\"");
    static ABNF challenge = REG.rule("challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]");
    static ABNF credentials = REG.rule("credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]");
    static ABNF WWWAuthenticate = REG.rule("WWW-Authenticate = 1#challenge");
    static ABNF authroization = REG.rule("Authorization = credentials");
    static ABNF proxyAuthenticate = REG.rule("Proxy-Authenticate = 1#challenge");
    static ABNF proxyAuthorization = REG.rule("Proxy-Authorization = credentials");
}
