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
