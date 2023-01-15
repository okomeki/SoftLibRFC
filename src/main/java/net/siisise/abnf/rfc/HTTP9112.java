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
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * RFC 9112 HTTP/1.1
 */
public class HTTP9112 {
    public static final ABNFReg REG = new ABNFReg(HTTP9110.REG,HTTP9110.PAR);

    // 1.2. Syntax Notation
    // RFC 5234 Appendix B.1
    private static final ABNF ALPHA = ABNF5234.ALPHA;
    private static final ABNF CR = ABNF5234.CR;
    private static final ABNF CRLF = ABNF5234.CRLF;
    private static final ABNF CTL = ABNF5234.CTL;
    private static final ABNF DIGIT = ABNF5234.DIGIT;
    private static final ABNF DQUOTE = ABNF5234.DQUOTE;
    private static final ABNF HEXDIG = ABNF5234.HEXDIG;
    private static final ABNF HTAB = ABNF5234.HTAB;
    private static final ABNF LF = ABNF5234.LF;
    private static final ABNF OCTET = ABNF5234.OCTET;
    private static final ABNF SP = ABNF5234.SP;
    private static final ABNF VCHAR = ABNF5234.VCHAR;
    
    // The rules below are defined in HTTP9110
    static final ABNF BWS = HTTP9110.BWS;
    static final ABNF OWS = HTTP9110.OWS;
    static final ABNF RWS = HTTP9110.RWS;
    static final ABNF absolutePath = HTTP9110.absolitePath;
    static final ABNF fieldName = HTTP9110.fieldName;
    static final ABNF fieldValue = HTTP9110.fieldValue;
    static final ABNF obsText = HTTP9110.obsText;
    static final ABNF quotedString = HTTP9110.quotedString;
    static final ABNF token = HTTP9110.token;
    static final ABNF transferCoding = HTTP9110.transferCoding;
    
    private static final ABNF absoluteURI = REG.rule("absolute-URI", URI3986.absoluteURI);
    private static final ABNF authority = REG.rule("authority", URI3986.authority);
    static final ABNF uriHost = REG.rule("uri-host", URI3986.host);
    static final ABNF port = REG.rule("port", URI3986.port);
    static final ABNF query = REG.rule("query", URI3986.query);
    
    // 5. Field Syntax
    public static final ABNF fieldLine = REG.rule("field-line", fieldName.pl(ABNF.bin(':'),OWS,fieldValue,OWS));
    // 7. Transfer Codings
    // 7.1.2. Chunked Trailer Section
    static final ABNF trailerSection = REG.rule("trailer-section", fieldLine.pl(CRLF).x());
    // 7.1.1. Chunk Extensions
    static final ABNF chunkExtVal = REG.rule("chunk-ext-val", token.or1(quotedString));
    static final ABNF chunkExtName = REG.rule("chunk-ext-name", token);
    static final ABNF chunkExt = REG.rule("chunk-ext", BWS.pl(ABNF.bin(';'),BWS,chunkExtName,BWS.pl(ABNF.bin('='),BWS,chunkExtVal).c()).x());
    // 7.1. Chunked Transfer Coding
    static final ABNF chunkData = REG.rule("chunk-data", OCTET.ix());
    static final ABNF lastChunk = REG.rule("last-chunk", ABNF.bin('0').ix().pl(chunkExt.c(),CRLF));
    static final ABNF chunkSize = REG.rule("chunk-size", HEXDIG.ix());
    static final ABNF chunk = REG.rule("chunk", chunkSize.pl(chunkExt.c(),CRLF));
    static final ABNF chunkedBody = REG.rule("chunked-body", chunk.x().pl(lastChunk,trailerSection,CRLF));

    // 6.1. Transfer-Encoding
    // transfer-coding iin HTTP9110 Section 10.1.4
    static final ABNF TransferEncoding = REG.rule("Transfer-Encoding", "#transfer-coding");
    // 6. Message Body
    static final ABNF messageBody = REG.rule("message-body", OCTET.x());
    // 5.2. Obsolete Line Folding
    static final ABNF obsFold = REG.rule("obs-fold", OWS.pl(CRLF, OWS));
    // 2.3. HTTP Version
    static final ABNF HTTPname = REG.rule("HTTP-name", ABNF.bin("HTTP"));
    static final ABNF HTTPversion = REG.rule("HTTPversion", HTTPname.pl(ABNF.bin('/'),DIGIT,ABNF.bin('.'),DIGIT));
    // 4. Status Line
    static final ABNF reasonPhrase = REG.rule("reason-phrase", HTAB.or1(SP,VCHAR,obsText).ix());
    static final ABNF statusCode = REG.rule("status-code", DIGIT.x(3));
    static final ABNF statusLine = REG.rule("status-line", HTTPversion.pl(SP, statusCode, SP, reasonPhrase.c()));
    
    
    // 3.2.4. asterisk-form
    static final ABNF asteriskForm = REG.rule("asterisk-form", ABNF.bin('*'));
    // 3.2.3. authority-form
    static final ABNF authorityForm = REG.rule("authority-form", uriHost.pl(ABNF.bin(':'),port));
    // 3.2.2. absolute-form
    static final ABNF absoluteForm = REG.rule("absolute-form", absoluteURI);
    // 3.2.1. origin-form
    static final ABNF originForm = REG.rule("origin-form", absolutePath.pl(ABNF.bin('?').pl(query).c()));
    // 3.2. Request Target
    static final ABNF requestTarget = REG.rule("request-target", originForm.or1(absoluteForm,authorityForm,asteriskForm));
    // 3.1. method
    // Section 9 of HTTP9110
    static final ABNF method = REG.rule("method", token);
    // 3. Request Line
    public static final ABNF requestLine = REG.rule("request-line", method.pl(SP,requestTarget,SP,HTTPversion));
    // 2.1. Message Format
    public static final ABNF startLine = REG.rule("start-line", requestLine.or1(statusLine));
    public static final ABNF HTTPmessage = REG.rule("HTTP-message", startLine.pl(CRLF, fieldLine.pl(CRLF).x(), CRLF, messageBody.c()) );
}
