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
 * IMF5322のFromなど修正
 *
 */
public class IMF6854 {

    public static final ABNFReg REG = new ABNFReg(IMF5322.REG);

    public static final ABNF from = REG.rule("from", "\"From:\" (mailbox-list / address-list) CRLF");
    public static final ABNF sender = REG.rule("sender", "\"Sender:\" (mailbox / address) CRLF");
    public static final ABNF replyTo = REG.rule("reply-to", "\"Reply-To:\" address-list CRLF");

    public static final ABNF resentFrom = REG.rule("resent-from", "\"Resent-From:\" (mailbox-list / address-list) CRLF");
    public static final ABNF resentSender = REG.rule("resent-sender", "\"Resent-Sender:\" (mailbox / address) CRLF");
}
