package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFCC;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * RFC 9110 HTTP Semantics
 * RFC 7230と同じ?
 */
public class HTTP9110 {

    static final ABNFCC PAR = new ABNFCC(ABNF5234.copyREG(), ABNF5234.REG);

    public static final ABNFReg REG = new ABNFReg(URI3986.REG, PAR);

    // Section 4.1. URI References RFC 7230と同じ
    static final ABNF URIreference = URI3986.URIreference;
    static final ABNF absoluteURI = REG.rule("absolute-URI", URI3986.absoluteURI);
    static final ABNF relativePart = URI3986.relativePart;
    static final ABNF authority = URI3986.authority;
    static final ABNF uriHost = REG.rule("uri-host", URI3986.host);
    static final ABNF port = URI3986.port;
    static final ABNF pathAbempty = URI3986.pathAbempty;
    static final ABNF segment = URI3986.segment;
    static final ABNF query = URI3986.query;

    static final ABNF absolitePath = REG.rule("absolute-path", "1*( \"/\" segment )");
    static final ABNF partialURI = REG.rule("partial-URI", relativePart.pl(ABNF.bin("?").pl(URI3986.query).c()));

    // Section 4.2. HTTP-Related URI Schemes RFC 7230と同じ
    static final ABNF httpURI = REG.rule("http-URI", ABNF.text("http").pl(ABNF.bin("://"), URI3986.authority, URI3986.pathAbempty, ABNF.text("?").pl(URI3986.query).c()));
    static final ABNF httpsURI = REG.rule("https-URI", "\"https\" \"://\" authority path-abempty [ \"?\" query ]");

    // Section 5.6.2. Tokens
    static final ABNF tchar = REG.rule("tchar", ABNF.list("!#$%&'*+-.^_`|~").or(ABNF5234.DIGIT, ABNF5234.ALPHA));
    static final ABNF token = REG.rule("token", tchar.ix());

    // Section 5.1. Field Names
    static final ABNF fieldName = REG.rule("field-name", token);

    static final ABNF obsFold = REG.rule("obs-fold", ABNF5234.CRLF.pl(ABNF5234.SP.or(ABNF5234.HTAB).ix()));

    // Section 5.5. Field Values
    static final ABNF obsText = REG.rule("obs-text", ABNF.range(0x80, 0xff));
    static final ABNF fieldVchar = REG.rule("field-vchar", "VCHAR / obs-text");
    static final ABNF fieldContent = REG.rule("field-content", "field-vchar [ 1*( SP / HTAB ) field-vchar ]");
    static final ABNF fieldValue = REG.rule("field-value", "*( field-content / obs-fold )");

    // Section 5.6.3. Whitespace
    static final ABNF OWS = REG.rule("OWS", ABNF5234.SP.or(ABNF5234.HTAB).x());
    static final ABNF RWS = REG.rule("RWS", ABNF5234.SP.or(ABNF5234.HTAB).ix());
    static final ABNF BWS = REG.rule("BWS", OWS);

    // Section 5.6.4. Quoted Strings
    static final ABNF qdtext = REG.rule("qdtext", ABNF5234.HTAB.or(ABNF5234.SP, ABNF.bin(0x21), ABNF.range(0x23, 0x5b), ABNF.range(0x5d, 0x7e), obsText));
    static final ABNF quotedString = REG.rule("quoted-string", "DQUOTE *( qdtext / quoted-pair ) DQUOTE");
    static final ABNF quotedPair = REG.rule("quoted-pair", "\"\\\" ( HTAB / SP / VCHAR / obs-text )");

    // Section 5.6.5. Comments
    static final ABNF ctext = REG.rule("ctext", ABNF5234.HTAB.or(ABNF5234.SP, ABNF.range(0x21, 0x27), ABNF.range(0x2a, 0x5b), ABNF.range(0x5d, 0x7e), obsText));
    static final ABNF comment = REG.rule("comment", "\"(\" *( ctext / quoted-pair / comment ) \")\"");
}
