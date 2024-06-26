/*
 * Copyright 2023 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFCC;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.abnf.parser5234.Repetition;

/**
 * RFC 7230 Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing
 * Section 7の拡張あり
 * RFC 6874 取り込んでない?
 * obsなし版も作りたい?
 * 
 * @deprecated RFC 9110,9112
 *
 * https://tools.ietf.org/html/rfc7230 Section 7
 * URI3986
 */
@Deprecated
public class HTTP7230 {

    public static final ABNFCC PAR = new ABNFCC(ABNF5234.copyREG(), ABNF5234.REG);

    // Section 7 ABNF Parserの拡張
    static final ABNF repList = PAR.rule("rep-list", ABNF5234.DIGIT.x().pl(ABNF.bin('#'), ABNF5234.DIGIT.x()).or(ABNF5234.DIGIT.ix()));
    static final ABNF orgrepetition = PAR.rule("orgrepetition", Repetition.class, PAR.href("repetition")); // 改名
    static final ABNF httprepetition = PAR.rule("httprepetition", HTTP7230Repetition.class, repList.pl(PAR.ref("element")));
    static final ABNF repetition = PAR.rule("repetition", HTTP7230RepetitionSelect.class, orgrepetition.or1(httprepetition));

    public static final ABNFReg REG = new ABNFReg(URI3986.REG, PAR);

    static final ABNF URIreference = URI3986.URIreference;
    static final ABNF absoluteURI = REG.rule("absolute-URI", URI3986.absoluteURI);
    static final ABNF relativePart = URI3986.relativePart;
    static final ABNF scheme = URI3986.scheme;
    static final ABNF authority = URI3986.authority;
    static final ABNF uriHost = REG.rule("uri-host", URI3986.host);
    static final ABNF port = URI3986.port;
    static final ABNF pathAbempty = URI3986.pathAbempty;
    static final ABNF segment = URI3986.segment;
    static final ABNF query = URI3986.query;
    static final ABNF fragment = URI3986.fragment;

    // 2.3.
    // HTTP9110 2.5.
    static final ABNF HTTPname = REG.rule("HTTP-name", "%x48.54.54.50");
    static final ABNF HTTPversion = REG.rule("HTTP-version", HTTPname.pl(ABNF.bin('/'),ABNF5234.DIGIT,ABNF.bin('.'), ABNF5234.DIGIT));

    static final ABNF absolitePath = REG.rule("absolute-path", ABNF.bin('/').pl(segment).ix());
    static final ABNF partialURI = REG.rule("partial-URI", relativePart.pl(ABNF.bin("?").pl(URI3986.query).c()));

    static final ABNF httpURI = REG.rule("http-URI", ABNF.text("http:").pl(ABNF.text("//"), URI3986.authority, URI3986.pathAbempty, ABNF.text("?").pl(URI3986.query).c()));
    static final ABNF httpsURI = REG.rule("https-URI", "\"https:\" \"//\" authority path-abempty [ \"?\" query ]");

    // 3.2.6.
    static final ABNF tchar = REG.rule("tchar", ABNF.list("!#$%&'*+-.^_`|~").or1(ABNF5234.DIGIT, ABNF5234.ALPHA));
    static final ABNF token = REG.rule("token", tchar.ix());

    static final ABNF quotedPair = REG.rule("quoted-pair", "\"\\\" ( HTAB / SP / VCHAR / obs-text )");
    static final ABNF obsText = REG.rule("obs-text", ABNF.range(0x80,0xff));
    static final ABNF qdtext = REG.rule("qdtext", "HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text");
    static final ABNF quotedString = REG.rule("quoted-string", "DQUOTE *( qdtext / quoted-pair ) DQUOTE");

    static final ABNF ctext = REG.rule("ctext", "HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text");
    static final ABNF comment = REG.rule("comment", "\"(\" *( ctext / quoted-pair / comment ) \")\"");

    // 5.3.1.
    static final ABNF originForm = REG.rule("origin-form", "absolute-path [ \"?\" query ]");
    // 5.3.2.
    static final ABNF absoluteForm = REG.rule("absolute-form", absoluteURI);
    // 5.3.3.
    static final ABNF authorityForm = REG.rule("authorityForm", authority);
    // 5.3.4.
    static final ABNF asteriskForm = REG.rule("asteriskForm", ABNF.bin("*"));
    // 5.3.
    static final ABNF requestTarget = REG.rule("request-target", originForm.or(absoluteForm, authorityForm, asteriskForm));

    // 3.1. start-line
    // 3.1.1. request-line
    static final ABNF method = REG.rule("method", token);
    public static final ABNF requestLine = REG.rule("request-line", method.pl(ABNF5234.SP,requestTarget,ABNF5234.SP,HTTPversion,ABNF5234.CRLF));
    // 3.1.2. status-line
    static final ABNF statusCode = REG.rule("status-code", ABNF5234.DIGIT.x(3));
    static final ABNF reasonPhrase = REG.rule("reason-phrase", ABNF5234.HTAB.or1(ABNF5234.SP,ABNF5234.VCHAR,obsText).x());
    static final ABNF statusLine = REG.rule("status-line", HTTPversion.pl(ABNF5234.SP, statusCode, ABNF5234.SP, reasonPhrase, ABNF5234.CRLF));
    // 3.1.
    public static final ABNF startLine = REG.rule("start-line", requestLine.or(statusLine));

    // 3.2. header-field
    // 3.2.3. 空白
    static final ABNF OWS = REG.rule("OWS", ABNF5234.SP.or1(ABNF5234.HTAB).x());
    static final ABNF RWS = REG.rule("RWS", ABNF5234.SP.or1(ABNF5234.HTAB).ix());
    static final ABNF BWS = REG.rule("BWS", OWS);

    static final ABNF fieldName = REG.rule("field-name", token);
    static final ABNF obsFold = REG.rule("obs-fold", ABNF5234.CRLF.pl(ABNF5234.SP.or1(ABNF5234.HTAB).ix()));
    static final ABNF fieldVchar = REG.rule("field-vchar", ABNF5234.VCHAR.or1(obsText));
    static final ABNF fieldContent = REG.rule("field-content", "field-vchar [ 1*( SP / HTAB ) field-vchar ]");
    static final ABNF fieldValue = REG.rule("field-value", fieldContent.or1(obsFold).x());
    public static final ABNF headerField = REG.rule("header-field", "field-name \":\" OWS field-value OWS");

    // 4. 転送符号法
    static final ABNF transferParameter = REG.rule("transfer-parameter", "token BWS \"=\" BWS ( token / quoted-string )");
    static final ABNF transferExtension = REG.rule("transfer-extension", "token *( OWS \";\" OWS transfer-parameter )");
    static final ABNF transferCoding = REG.rule("transfer-coding", "\"chunked\" / \"compress\" / \"deflate\" / \"gzip\" / transfer-extension");

    // 3.3. メッセージ本体
    static final ABNF messageBody = REG.rule("message-body", ABNF5234.OCTET.x());

    static final ABNF transferEncoding = REG.rule("Transfer-Encoding", "1#transfer-coding");
    static final ABNF ContentLength = REG.rule("Content-Length", ABNF5234.DIGIT.ix());

    // 4.1.1.
    static final ABNF chunkExtVal = REG.rule("chunk-ext-val", token.or(quotedString));
    static final ABNF chunkExtName = REG.rule("chunk-ext-name", token);
    static final ABNF chunkExt = REG.rule("chunk-ext", "*( BWS \";\" BWS chunk-ext-name [ BWS \"=\" BWS chunk-ext-val ] )");

    // 4.1.2.
    static final ABNF trailerPart = REG.rule("trailer-part", "*( header-field CRLF )");

    // 4.1.
    static final ABNF chunkSize = REG.rule("chunk-size", ABNF5234.HEXDIG.ix());
    static final ABNF chunkData = REG.rule("chunk-data", ABNF5234.OCTET.ix());
    static final ABNF chunk = REG.rule("chunk", "chunk-size [ chunk-ext ] CRLF chunk-data CRLF");
    static final ABNF lastChunk = REG.rule("last-chunk", "1*(\"0\") [ chunk-ext ] CRLF");
    public static final ABNF chunkedBody = REG.rule("chunked-body", "*chunk last-chunk trailer-part CRLF");

    // 3.メッセージ形式
    public static final ABNF HTTPmessage = REG.rule("HTTP-message", "start-line *( header-field CRLF ) CRLF [ message-body ]");

    // 4.3.
    static final ABNF rank = REG.rule("rank", "( \"0\" [ \".\" 0*3DIGIT ] ) / ( \"1\" [ \".\" 0*3(\"0\") ] )");
    static final ABNF tRanking = REG.rule("t-ranking", "OWS \";\" OWS \"q=\" rank");
    static final ABNF tCodings = REG.rule("t-codings", "\"trailers\" / ( transfer-coding [ t-renking ] )");
    public static final ABNF TE = REG.rule("TE", "#t-codings");
    // 4.4.
    public static final ABNF Trailer = REG.rule("Trailer", "1#field-name");
    // 5.4.
    public static final ABNF Host = REG.rule("Host", "uri-host [ \":\" port ]");
    // 5.7.
    static final ABNF receivedProtocol = REG.rule("received-protocol", "[ protocol-name \"/\" ] protocol-version");
    static final ABNF pseudonym = REG.rule("pseudonym", token); // pseudo + anonymous  疑似匿名 (仮名)
    static final ABNF receivedBy = REG.rule("received-by", "( uri-host [ \":\" port ] ) / pseudonym");
    public static final ABNF Via = REG.rule("Via", "1#( received-protocol RWS received-by [ RWS comment ] )");
    // 6.1.
    static final ABNF connectionOption = REG.rule("connection-option", token);
    public static final ABNF Connection = REG.rule("Connection", "1#connection-option");
    // 6.7.
    static final ABNF protocolName = REG.rule("protocol-name", token);
    static final ABNF protocolVersion = REG.rule("protocol-version", token);
    static final ABNF protocol = REG.rule("protocol", "protocol-name [\"/\" protocol-version]");
    public static final ABNF Upgrade = REG.rule("Upgrade", "1#protocol");
}
