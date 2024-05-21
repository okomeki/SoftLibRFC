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

/**
 * RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 * @deprecated RFC 7235
 */
@Deprecated
public class HTTPAuthentication2617 {

    public static final ABNFReg REG = new ABNFReg(HTTP2616.REG, HTTP7230.PAR);

    // 1.2 Access Authentication Framework
    static final ABNF authScheme = REG.rule("auth-scheme", HTTP2616.token);
    static final ABNF authParam = REG.rule("auth-param", HTTP2616.token.pl(ABNF.bin('='), HTTP2616.token.or1(HTTP2616.quotedString)));

    static final ABNF domain = REG.rule("domain", ABNF.text("domain"));
    static final ABNF digestChallenge = REG.rule("digest-challenge", "1#(realm|[domain]|nonce|[opaque]|[stale]|[algorithm]|[qop-options]|[auth-param])");
    //ABNF.text("Digest").pl(digestChallenge));
    static final ABNF realmValue = REG.rule("realm-value", HTTP2616.quotedString);
    static final ABNF realm = REG.rule("realm", ABNF.text("realm").pl(ABNF.bin('='),realmValue));

    static final ABNF challenge = REG.rule("challenge", authScheme.pl(HTTP2616.SP.ix(), REG.elements("1#auth-param")));
    static final ABNF credentials = REG.rule("credentials", authScheme.pl(REG.elements("#auth-param")));

    // 2. Basic Authentication Scheme
    static final ABNF bChallenge = REG.rule("challenge", ABNF.text("Basic").pl(realm));
    static final ABNF userid = REG.rule("userid", HTTP2616.TEXT.mn(ABNF.bin(':')).x());
    static final ABNF password = REG.rule("password", HTTP2616.TEXT.x());
    static final ABNF userPass = REG.rule("user-pass",userid.pl(ABNF.bin(':'),password));
    static final ABNF token68 = REG.rule("token68", HTTP2616.ALPHA.or1(HTTP2616.DIGIT, ABNF.binlist("-._~+/")).ix().pl(ABNF.bin('=').x())); // 7235のtoken68を追加
    static final ABNF base64userPass = REG.rule("base64-user-pass", token68); // BASE64で76文字改行のuser-pass
    static final ABNF basicCredentials = REG.rule("basic-credentials", base64userPass);
    static final ABNF bCredentials = REG.rule("credentials", ABNF.text("Basic").pl(basicCredentials));

}
