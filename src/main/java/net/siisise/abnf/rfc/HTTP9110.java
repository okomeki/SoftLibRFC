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
 * RFC 9110 HTTP Semantics
 * まだ RFC 7230 のコピペ気味
 * RFC 7230, RFC 7235 など
 */
public class HTTP9110 {

    private static final ABNF SP = ABNF5234.SP;
    private static final ABNF HTAB = ABNF5234.HTAB;
    private static final ABNF VCHAR = ABNF5234.VCHAR;
    private static final ABNF ALPHA = ABNF5234.ALPHA;
    private static final ABNF DIGIT = ABNF5234.DIGIT;

    static final ABNFCC PAR = new ABNFCC(ABNF5234.copyREG(), ABNF5234.REG);
//    static final ABNFCC PAR = new ABNFCC(ABNF5234.copyREG(), ABNF5234.REG);

    // 5.6. RFC 7230 Section 7 ABNF Parsetの拡張実験 RFC 9110 はまだ見てない
    static final ABNF repList = PAR.rule("rep-list", DIGIT.x().pl(ABNF.bin('#'), DIGIT.x()).or(DIGIT.ix()));
    static final ABNF orgrepetition = PAR.rule("orgrepetition", Repetition.class, PAR.href("repetition")); // 改名
    static final ABNF httprepetition = PAR.rule("httprepetition", HTTP7230Repetition.class, repList.pl(PAR.ref("element")));
    static final ABNF repetition = PAR.rule("repetition", HTTP7230RepetitionSelect.class, "orgrepetition / httprepetition");

    /**
     * 2.1. RFC 5234 B.1 を含む
     */
    public static final ABNFReg REG = new ABNFReg(URI3986.REG, PAR);
    
    // Section 4.1. URI References RFC 7230と同じ
    private static final ABNF URIreference = URI3986.URIreference;
    private static final ABNF absoluteURI = REG.rule("absolute-URI", URI3986.absoluteURI);
    private static final ABNF relativePart = URI3986.relativePart;
    private static final ABNF authority = URI3986.authority;
    static final ABNF uriHost = REG.rule("uri-host", URI3986.host);
    private static final ABNF port = URI3986.port;
    private static final ABNF pathAbempty = URI3986.pathAbempty;
    private static final ABNF segment = URI3986.segment;
    private static final ABNF query = URI3986.query;

    static final ABNF absolitePath = REG.rule("absolute-path", "1*( \"/\" segment )");
    static final ABNF partialURI = REG.rule("partial-URI", relativePart.pl(ABNF.bin("?").pl(query).c()));

    // Section 4.2. HTTP-Related URI Schemes RFC 7230と同じ
    static final ABNF httpURI = REG.rule("http-URI", ABNF.text("http").pl(ABNF.bin("://"), authority, pathAbempty, ABNF.bin('?').pl(query).c()));
    static final ABNF httpsURI = REG.rule("https-URI", ABNF.text("https").pl(ABNF.bin("://"), authority, pathAbempty, ABNF.bin('?').pl(query).c()));

    // Section 5.6.2. Tokens
    static final ABNF tchar = REG.rule("tchar", ABNF.binlist("!#$%&'*+-.^_`|~").or1(DIGIT, ALPHA));
    static final ABNF token = REG.rule("token", tchar.ix());

    // Section 5.1. Field Names
    static final ABNF fieldName = REG.rule("field-name", token);

    // Section 5.5. Field Values
    static final ABNF obsText = REG.rule("obs-text", ABNF.range(0x80, 0xff));
    static final ABNF fieldVchar = REG.rule("field-vchar", VCHAR.or1(obsText));
    static final ABNF fieldContent = REG.rule("field-content", fieldVchar.pl(SP.or1(ABNF5234.HTAB, fieldVchar).ix().plu(fieldVchar).c()));
    static final ABNF fieldValue = REG.rule("field-value", fieldContent.x());

    // Section 5.6.3. Whitespace
    static final ABNF OWS = REG.rule("OWS", SP.or1(HTAB).x());
    static final ABNF RWS = REG.rule("RWS", SP.or1(HTAB).ix());
    static final ABNF BWS = REG.rule("BWS", OWS);

    // Section 5.6.4. Quoted Strings
    static final ABNF qdtext = REG.rule("qdtext", HTAB.or1(SP, ABNF.bin(0x21), ABNF.range(0x23, 0x5b), ABNF.range(0x5d, 0x7e), obsText));
    static final ABNF quotedPair = REG.rule("quoted-pair", ABNF.bin('\\').pl( HTAB.or1(SP, VCHAR, obsText)));
    static final ABNF quotedString = REG.rule("quoted-string", ABNF5234.DQUOTE.pl(qdtext.or1(quotedPair).x(), ABNF5234.DQUOTE));

    // Section 5.6.5. Comments
    static final ABNF ctext = REG.rule("ctext", HTAB.or(SP, ABNF.range(0x21, 0x27), ABNF.range(0x2a, 0x5b), ABNF.range(0x5d, 0x7e), obsText));
    static final ABNF comment = REG.rule("comment", ABNF.bin('(').pl( ctext.or1(quotedPair, REG.ref("comment")).x(), ABNF.bin(')')));
    
    // Section 5.6.6. Parameters
    static final ABNF parameterName = REG.rule("parameter-name", token);
    static final ABNF parameterValue = REG.rule("parameter-value", token.or1(quotedString));
    static final ABNF parameter = REG.rule("parameter", parameterName.pl(ABNF.bin('='),parameterValue));
    static final ABNF parameters = REG.rule("parameters", OWS.pl(ABNF.bin(';'),OWS, parameter.c()));
    
    // Section 5.6.7. Date/Time Formats
    static final ABNF dayName = REG.rule("day-name", ABNF.bin("Mon").or1(ABNF.bin("Tue"), ABNF.bin("Wed"),
            ABNF.bin("Thu"), ABNF.bin("Fri"), ABNF.bin("Sat"), ABNF.bin("Sun")));
    static final ABNF day = REG.rule("day", ABNF5234.DIGIT.x(2));
    static final ABNF month = REG.rule("month", ABNF.bin("Jan").or1(ABNF.bin("Feb"),ABNF.bin("Mar"),ABNF.bin("Apr"),
            ABNF.bin("May"),ABNF.bin("Jun"),ABNF.bin("Jul"),ABNF.bin("Aug"),
            ABNF.bin("Sep"),ABNF.bin("Oct"),ABNF.bin("Nov"),ABNF.bin("Dec")));
    static final ABNF year = REG.rule("year", ABNF5234.DIGIT.x(4));
    static final ABNF date1 = REG.rule("date1", day.pl(SP,month,SP,year));
    static final ABNF GMT = REG.rule("GMT",ABNF.bin("GMT"));
    static final ABNF hour = REG.rule("hour", DIGIT.x(2));
    static final ABNF minute = REG.rule("minute", DIGIT.x(2));
    static final ABNF second = REG.rule("second", DIGIT.x(2));
    static final ABNF timeOfDay = REG.rule("time-of-day", hour.pl(ABNF.bin(':'),minute,ABNF.bin(':'),second));
    static final ABNF IMFfixdate = REG.rule("IMFfixdate", dayName.pl(ABNF.bin(','),SP,date1,SP, timeOfDay,SP,GMT));
    static final ABNF date2 = REG.rule("date2", day.pl(ABNF.bin('-'),month,ABNF.bin('-'),DIGIT.x(2)));
    static final ABNF dayNameL = REG.rule("day-name-l", ABNF.bin("Monday").or1(ABNF.bin("Tuesday"),ABNF.bin("Wednesday"),
            ABNF.bin("Thursday"),ABNF.bin("Friday"),ABNF.bin("Saturday"),ABNF.bin("Sunday")));
    static final ABNF rfc850date = REG.rule("rfc850-date", dayNameL.pl(ABNF.bin(','),date2,SP,timeOfDay,SP,GMT));
    static final ABNF date3 = REG.rule("date3", month.pl(SP,DIGIT.x(2).or1(SP.pl(DIGIT))));
    static final ABNF asctimeDate = REG.rule("asctime-date", dayName.pl(SP,date3,SP,timeOfDay,SP,year));
    static final ABNF obsDate = REG.rule("obs-date", rfc850date.or1(asctimeDate));
    static final ABNF HTTPdate = REG.rule("HTTP-date", IMFfixdate.or1(obsDate));
    // 6.6.1. Date
    static final ABNF Date = REG.rule("Date", HTTPdate);
    // 6.6.2. Trailer
    static final ABNF Trailer = REG.rule("Trailer","#field-name");
    // 7.2. Host
    static final ABNF Host = REG.rule("Host", uriHost.pl(ABNF.bin(':').pl(port).c()));
    // 7.6.1. Connection
    static final ABNF connectionOption = REG.rule("connection-option", token);
    static final ABNF Connection = REG.rule("Connection", "#connection-option");
    // 7.6.2. Max-Forwards
    static final ABNF MaxForwards = REG.rule("Max-Forwards", DIGIT.ix());
    // 7.8. Upgrade
    static final ABNF protocolName = REG.rule("protocol-name", token);
    static final ABNF protocolVersion = REG.rule("protocol-version", token);
    static final ABNF protocol = REG.rule("protocol", protocolName.pl(ABNF.bin('/').pl(protocolVersion).c()));
    static final ABNF Upgrade = REG.rule("Upgrade", "#protocol");
    // 7.6.3. Via
    static final ABNF pseudonym = REG.rule("pseudonym", token);
    static final ABNF receivedBy = REG.rule("received-by", pseudonym.pl(ABNF.bin(':').pl(port).c()));
    static final ABNF receivedProtocol = REG.rule("received-protocol", protocolName.pl(ABNF.bin('/').c().pl(protocolVersion)));
    static final ABNF Via = REG.rule("Via", "#( received-protocol RWS received-by [ RWS comment ] )");
    
    // 8.1. Representation Data
//    static final ABNF representationData = REG.rule("representation-data","");
    static final ABNF type = REG.rule("type", token);
    static final ABNF subtype = REG.rule("subtype", token);
    static final ABNF mediaType = REG.rule("media-type",type.pl(ABNF.bin('/'),subtype,parameters));
    static final ABNF contentType = REG.rule("Content-Type", mediaType);
    
    // 8.4. Content-Encoding
    static final ABNF contentCoding = REG.rule("content-coding", token);
    static final ABNF ContentEncoding = REG.rule("Content-Encoding","#content-coding");
    // 8.5. Content-Language
    static final ABNF languageTag = REG.rule("language-tag", Lang5646.Language_Tag);
    static final ABNF conentLanguage = REG.rule("Content-Language","#language-tag");
    // 8.6. Content-length
    static final ABNF ContentLength = REG.rule("Content-Length", DIGIT.ix());
    // 8.7. Content-Location
    static final ABNF ContentLocation = REG.rule("Content-Location", absoluteURI.or(partialURI));
    // 8.8.2. Last-Modified
    static final ABNF LastModified = REG.rule("Last-Modified", HTTPdate);
    // 8.8.3. ETag
    static final ABNF etagc = REG.rule("etagc", ABNF.bin(0x21).or1(ABNF.range(0x23,0x7e),obsText));
    static final ABNF opaqueTag = REG.rule("opaque-tag", ABNF5234.DQUOTE.pl(etagc.x(),ABNF5234.DQUOTE));
    static final ABNF weak = REG.rule("weak", ABNF.bin("W/"));
    static final ABNF entityTag = REG.rule("entity-tag",weak.c().pl(opaqueTag));
    static final ABNF ETag = REG.rule("ETag",entityTag);
    // 9.Methods 9.1.Overview
    static final ABNF method = REG.rule("method", token);
    // 10.1.1. Expect
    static final ABNF expectation = REG.rule("expectation", token.pl(ABNF.bin('=').pl(token.or1(quotedString),parameters).c()));
    static final ABNF Expect = REG.rule("Expect", "#expectation");
    
    // 10.1.2. From
    static final ABNF mailbox = REG.rule("mailbox", IMF5322.mailbox); // RFC5322 Section 3.4
    static final ABNF From = REG.rule("From", mailbox);
    
    static final ABNF Referer = REG.rule("Referer", absoluteURI.or1(partialURI));
    
    static final ABNF qvalue = REG.rule("qvalue", ABNF.bin('0').pl(ABNF.bin('.').pl(DIGIT.x(0,3)).c()).or1(
            ABNF.bin('1').pl(ABNF.bin('.').pl(ABNF.bin('0').x(0,3)).c())));
    static final ABNF weight = REG.rule("weight", OWS.pl(ABNF.bin(';'),OWS, ABNF.text("q="), qvalue));
    
    static final ABNF transferParameter = REG.rule("teansfer-parameter", token.pl(BWS,ABNF.bin('='),BWS,token.or1(quotedString)));
    static final ABNF transferCoding = REG.rule("transfer-coding", token.pl(OWS.pl(ABNF.bin(';'),OWS,transferParameter).x()));
    static final ABNF tCondigs = REG.rule("t-codings", ABNF.text("trailers").or(transferCoding.pl(weight.c())));
    static final ABNF TE = REG.rule("TE","#t-codings");
    
    static final ABNF productVersion = REG.rule("product-version", token);
    static final ABNF product = REG.rule("product",token.pl(ABNF.bin('/').pl(productVersion)));
    static final ABNF UserAgent = REG.rule("User-Agent", product.pl( RWS.pl(product.or1(comment)).x()));
    
    static final ABNF Allow = REG.rule("Allow", "#method");
    
    static final ABNF Location = REG.rule("Location",URIreference);
    
    static final ABNF delaySeconds = REG.rule("delay-seconds", DIGIT.ix());
    static final ABNF RetryAfter = REG.rule("Retry-After", HTTPdate.or1(delaySeconds));
    
    static final ABNF Server = REG.rule("Server", product.pl(RWS.pl(product.or1(comment)).x()));
    // 11
    static final ABNF authScheme = REG.rule("auth-scheme", token);
    static final ABNF token68 = REG.rule("token68", ALPHA.or1(DIGIT, ABNF.binlist("-._~+/")).ix().pl(ABNF.bin('=').x()));
    static final ABNF authParam = REG.rule("auth-param", token.pl(BWS,ABNF.bin('='),BWS,token.or1(quotedString)));
    //11.3. Challenge and Response
    static final ABNF challenge = REG.rule("challenge", authScheme.pl(SP.ix().pl(token68.or1(REG.elements("#auth-param"))).c()));
    static final ABNF credentials = REG.rule("credentials", authScheme.pl(SP.ix().pl(token68.or1(REG.elements("#auth-param"))).c()));
    // 11.6.1. WWW-Authenticate
    static final ABNF WWWAuthenticate = REG.rule("WWW-Authenticate", "#challenge");
    // 11.6.2. Authorication
    static final ABNF Authorization = REG.rule("Authorization", credentials);
    // 11.6.3. Authentication-Info
    static final ABNF AuthenticationInfo = REG.rule("Authentication-Info", "#auth-param");
    // 11.7.
    static final ABNF ProxyAuthenticate = REG.rule("Proxy-Authenticate", "#challenge");
    static final ABNF ProxyAuthorization = REG.rule("Proxy-Authorization", credentials);
    static final ABNF ProxyAuthenticationInfo = REG.rule("Proxy-Authentication-Info", "#auth-param");

    static final ABNF mediaRange = REG.rule("media-range", ABNF.bin("*/*").or1(type.pl(ABNF.bin("/*")), type.pl(ABNF.bin('/'), subtype).pl(parameters)));
    static final ABNF Accept = REG.rule("Accept","#( media-range [ weight ] )");
    // 12.5.2.
    static final ABNF AcceptCharset = REG.rule("Accept-Charset", "#( ( token / \"*\" ) [ weight ] )");
    
  
}
