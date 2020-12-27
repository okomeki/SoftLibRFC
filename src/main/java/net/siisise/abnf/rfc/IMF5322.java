package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * RFC 5322 Internet Message Format.
 * 動作未確認
 * REG obs省略版
 * OBS 全機能版
 */
public class IMF5322 {

    /**
     * obsを省いた定義
     */
    public static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    // 3.2.1.
//    static ABNF quotedPair = REG.rule("quoted-pair", ABNF.bin('\\').pl(ABNF5234.VCHAR.or(ABNF5234.WSP)));
    static final ABNF quotedPair = REG.rule("quoted-pair", "(\"\\\" (VCHAR / WSP)) / obs-qp");
    // 3.2.2.
    static final ABNF FWS = REG.rule("FWS", "([*WSP CRLF] 1*WSP) / obs-FWS");
    static final ABNF ctext = REG.rule("ctext", "%d33-39 / %d42-91 / %d93-126 / obs-ctext");
    static final ABNF comment = REG.rule("comment", "\"(\" *([FWS] ccontent) [FWS] \")\"");
    static final ABNF ccontent = REG.rule("ccontent", ctext.or(quotedPair, comment));
    static final ABNF CFWS = REG.rule("CFWS", "(1*([FWS] comment) [FWS]) / FWS");
    // 3.2.3. Atom
    static final ABNF atext = REG.rule("atext", ABNF5234.ALPHA.or(ABNF5234.DIGIT, ABNF.list("!#$%&'*+-/=?^_`{|}~")));
    static final ABNF atom = REG.rule("atom", CFWS.c().pl(atext.ix(),CFWS.c()));
    static final ABNF dotAtomText = REG.rule("dot-atom-text", "1*atext *(\".\" 1*atext)");
    static final ABNF dotAtom = REG.rule("dot-atom", "[CFWS] dot-atom-text [CFWS]");
    static final ABNF specials = REG.rule("specials", ABNF.list("()<>[]:;@\\,.").or(ABNF5234.DQUOTE));

    // 3.2.4. Quoted Strings
//    static ABNF qtext = REG.rule("qtext", "%d33 / %d35-91 / %d93-126");
    static final ABNF qtext = REG.rule("qtext", "%d33 / %d35-91 / %d93-126 / obs-qtext");
    static final ABNF qcontent = REG.rule("qcontent", qtext.or(quotedPair));
    static final ABNF quotedString = REG.rule("quoted-string", "[CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]");

    // 4.1. Miscellaneous Obsolete Tokens
    static final ABNF obsNoWsCtl = REG.rule("obs-NO-WS-CTL", "%d1-8 / %d11 / %d12 / %d14-31 / %d127");
    static final ABNF obsCtext = REG.rule("obs-ctext", obsNoWsCtl);
    static final ABNF obsQtext = REG.rule("obs-qtext", obsNoWsCtl);
    static final ABNF obsUtext = REG.rule("obs-utext", ABNF.bin(0x0).or(obsNoWsCtl, ABNF5234.VCHAR));
    static final ABNF obsQp = REG.rule("obs-qp", "\"\\\" (%d0 / obs-NO-WS-CTL / LF / CR)");
    static final ABNF obsBody = REG.rule("obs-body", "*((*LF *CR *((%d0 / text) *LF *CR)) / CRLF)");
//    static ABNF obsUnstruct = OBS.rule("obs-unstruct", "*((*LF *CR *(obs-utext *LF *CR)) / FWS)");
    static final ABNF obsUnstruct = REG.rule("obs-unstruct", "*( (*CR 1*(obs-utext / FWS)) / 1*LF ) *CR"); // Errata ID: 1905
    static final ABNF obsPhrase = REG.rule("obs-phrase", "word *(word / \".\" / CFWS)");
    static final ABNF obsPhraseList = REG.rule("obs-phrase-list", "[phrase / CFWS] *(\",\" [phrase / CFWS])");

    // 3.2.5. Miscellaneous Tokens
    static final ABNF word = REG.rule("word", atom.or(quotedString));
//    static ABNF phrase = REG.rule("phrase", word.ix());
    static final ABNF phrase = REG.rule("phrase", word.ix().or(obsPhrase));
//    static ABNF unstructured = REG.rule("unstructured", "(*([FWS] VCHAR) *WSP)");
    static final ABNF unstructured = REG.rule("unstructured", "(*([FWS] VCHAR) *WSP) / obs-unstruct");

    // 3.3. Date and Time Specification
    static final ABNF dayName = REG.rule("day-name", "\"Mon\" / \"Tue\" / \"Wed\" / \"Thu\" / \"Fri\" / \"Sat\" / \"Sun\"");
//    static ABNF dayOfWeek = REG.rule("day-of-week", "([FWS] day-name)");
    static final ABNF dayOfWeek = REG.rule("day-of-week", "([FWS] day-name) / obs-day-of-week");
//    static ABNF day = REG.rule("day", "([FWS] 1*2DIGIT FWS)");
    static final ABNF day = REG.rule("day", "([FWS] 1*2DIGIT FWS) / obs-day");
    static final ABNF date = REG.rule("date", "day month year");
    static final ABNF dateTime = REG.rule("date-time", "[ day-of-week \",\" ] date time [CFWS]");
    static final ABNF month = REG.rule("month", "\"Jan\" / \"Feb\" / \"Mar\" / \"Apr\" / "
            + "\"May\" / \"Jun\" / \"Jul\" / \"Aug\" / \"Sep\" / \"Oct\" / \"Nov\" / \"Dec\"");
    static final ABNF year = REG.rule("year", "(FWS 4*DIGIT FWS) / obs-year");
    static final ABNF hour = REG.rule("hour", "2DIGIT / obs-hour");
    static final ABNF minute = REG.rule("minute", "2DIGIT / obs-minute");
    static final ABNF second = REG.rule("second", "2DIGIT / obs-second");
    static final ABNF timeOfDay = REG.rule("time-of-day", "hour \":\" minute [ \":\" second ]");
    static final ABNF zone = REG.rule("zone", "(FWS ( \"+\" / \"-\" ) 4DIGIT) / obs-zone");
    static final ABNF time = REG.rule("time", "time-of-day zone");

    // 4.4. Obsolete Addressing
    static final ABNF obsAngleAddr = REG.rule("obs-angle-addr", "[CFWS] \"<\" obs-route addr-spec \">\" [CFWS]");
    static final ABNF obsRoute = REG.rule("obs-route", "obs-domain-list \":\"");
    static final ABNF obsDomainList = REG.rule("obs-domain-list", "*(CFWS / \",\") \"@\" domain *(\",\" [CFWS] [\"@\" domain])");
    static final ABNF obsMboxList = REG.rule("obs-mbox-list", "*([CFWS] \",\") mailbox *(\",\" [mailbox / CFWS])");
    static final ABNF obsAddrList = REG.rule("obs-addr-list", "*([CFWS] \",\") address *(\",\" [address / CFWS])");
    static final ABNF obsGroupList = REG.rule("obs-group-list", "1*([CFWS] \",\") [CFWS]");
    static final ABNF obsLocalPart = REG.rule("obs-local-part", "word *(\".\" word)");
    static final ABNF obsDomain = REG.rule("obs-domain", "atom *(\".\" atom)");
    static final ABNF obsDtext = REG.rule("obs-dtext", obsNoWsCtl.or(quotedPair));

    // 3.4.1. Addr-Spac Specification
//    static ABNF dtext = REG.rule("dtext", "%d33-90 / %d94-126");
    static final ABNF dtext = REG.rule("dtext", "%d33-90 / %d94-126 / obs-dtext");
    static final ABNF domainLiteral = REG.rule("domain-literal", "[CFWS] \"[\" *([FWS] dtext) [FWS] \"]\" [CFWS]");
    static final ABNF domain = REG.rule("domain", dotAtom.or(domainLiteral, obsDomain));
    public static final ABNF localPart = REG.rule("local-part", dotAtom.or(quotedString, obsLocalPart));
    public static final ABNF addrSpec = REG.rule("addr-spec", "local-part \"@\" domain");

    // 3.4. Address Specification
    static final ABNF angleAddr = REG.rule("angle-addr", "[CFWS] \"<\" addr-spec \">\" [CFWS] / obs-angle-addr");
    static final ABNF displayName = REG.rule("display-name", phrase);
    public static final ABNF nameAddr = REG.rule("name-addr", "[display-name] angle-addr");
    public static final ABNF mailbox = REG.rule("mailbox", nameAddr.or(addrSpec));
    static final ABNF group = REG.rule("group", "display-name \":\" [group-list] \";\" [CFWS]");
    public static final ABNF address = REG.rule("address", mailbox.or(group));
    static final ABNF mailboxList = REG.rule("mailbox-list", "(mailbox *(\",\" mailbox)) / obs-mbox-list");
    static final ABNF addressList = REG.rule("address-list", "(address *(\",\" address)) / obs-addr-list");
    static final ABNF groupList = REG.rule("group-list", "mailbox-list / CFWS / obs-group-list");
    // 3.5. Overall Message Syntax
    static final ABNF text = REG.rule("text", "%d1-9 / %d11 / %d12 / %d14-127");
    static final ABNF body = REG.rule("body", "(*(*998text CRLF) *998text) / obs-body");
    public static final ABNF message = REG.rule("message", "(fields / obs-fields) [CRLF body]");
    static final ABNF fields = REG.rule("fields", "*(trace"
            + "  *optional-field /"
            + "  *(resent-date /"
            + "   resent-from /"
            + "   resent-sender /"
            + "   resent-to /"
            + "   resent-cc /"
            + "   resent-bcc /"
            + "   resent-msg-id))"
            + " *(orig-date /"
            + " from /"
            + " sender /"
            + " reply-to /"
            + " to /"
            + " cc /"
            + " bcc /"
            + " message-id /"
            + " in-reply-to /"
            + " references /"
            + " subject /"
            + " comments /"
            + " keywords /"
            + " optional-field)");
    // 3.6.1. The Origination Date Field
    static final ABNF origDate = REG.rule("orig-date", "\"Date:\" date-time CRLF");
    // 3.6.2. Originator Fields
    // from, sender, replyToは差し替え対象なので直利用しない方がいい
    static final ABNF from = REG.rule("from", "\"From:\" mailbox-list CRLF");
    static final ABNF sender = REG.rule("sender", "\"Sender:\" mailbox CRLF");
    static final ABNF replyTo = REG.rule("reply-to", "\"Reply-To:\" address-list CRLF");
    // 3.6.3. Destination Address Fields
    static final ABNF to = REG.rule("to", "\"To:\" address-list CRLF");
    static final ABNF cc = REG.rule("cc", "\"Cc:\" address-list CRLF");
    static final ABNF bcc = REG.rule("bcc", "\"Bcc:\" [address-list / CFWS] CRLF");
    // 3.6.4.
    static final ABNF msgId = REG.rule("msg-id", "[CFWS] \"<\" id-left \"@\" id-right \">\" [CFWS]");
    static final ABNF messageId = REG.rule("message-id", "\"Message-ID:\" msg-id CRLF");
    static final ABNF inReplyTo = REG.rule("in-reply-to", "\"In-Reply-To:\" 1*msg-id CRLF");
    static final ABNF references = REG.rule("references", "\"References:\" 1*msg-id CRLF");
    static final ABNF idLeft = REG.rule("id-left", "dot-atom-text / obs-id-left");
    static final ABNF idRight = REG.rule("id-right", "dot-atom-text / no-field-literal / obs-id-right");
    static final ABNF noFoldLiteral = REG.rule("no-fold-literal", "\"[\" *dtext \"]\"");


    // 3.6.5. Informational Fields
    static final ABNF subject = REG.rule("subject", "\"Subject:\" unstructured CRLF");
    static final ABNF comments = REG.rule("comments", "\"Comments:\" unstructured CRLF");
    static final ABNF keywords = REG.rule("keywords", "\"Keywords:\" phrase *(\",\" phrase) CRLF");

    static final ABNF resentDate = REG.rule("resent-date", "\"Resent-Date:\" date-time CRLF");
    static final ABNF resentFrom = REG.rule("resent-from", "\"Resent-From:\" mailbox-list CRLF");
    static final ABNF resentSender = REG.rule("resent-sender", "\"Resent-Sender:\" mailbox CRLF");
    static final ABNF resentTo = REG.rule("resent-to", "\"Resent-To:\" address-list CRLF");
    static final ABNF resentCc = REG.rule("resent-cc", "\"Resent-Cc:\" address-list CRLF");
    static final ABNF resentBcc = REG.rule("resent-bcc", "\"Resent-Bcc:\" [address-list / CFWS] CRLF");
    static final ABNF resentMsgId = REG.rule("resent-msg-id", "\"Resent-Message-ID:\" msg-id CRLF");
    // 3.6.7. Trace Fields
    static final ABNF path = REG.rule("path", "angle-addr / ([CFWS] \"<\" [CFWS] \">\" [CFWS])");
    static final ABNF Return = REG.rule("return", "\"Return-Path:\" path CRLF");
    static final ABNF receivedToken = REG.rule("received-token", word.or(angleAddr, addrSpec, domain));
//    static ABNF received = REG.rule("received", "\"Received:\" *received-token \";\" date-time CRLF");
    static final ABNF received = REG.rule("received", "\"Received:\" [1*received-token / CFWS] \";\" date-time CRLF"); // Errata ID: 3979
    static final ABNF trace = REG.rule("trace", "[return] 1*received");

    // 3.6.8. Optional Fields
    static final ABNF ftext = REG.rule("ftext", "%d33-57 / %d59-126");
    static final ABNF fieldName = REG.rule("field-name", ftext.ix());
    static final ABNF optionalFields = REG.rule("optional-field", "field-name \":\" unstructured CRLF");
    // 4. Obsolete Syntax
    // 4.2. Obsolete Folding White Space
//    static ABNF obsFWS = OBS.rule("obs-FWS", "1*WSP *(CRLF 1*WSP)");
    static final ABNF obsFWS = REG.rule("obs-FWS", "1*([CRLF] WSP)"); // Errata ID: 1908

    // 4.3. Obsolete Date and Time
    static final ABNF obsDayOfWeek = REG.rule("obs-day-of-week", "[CFWS] day-name [CFWS]");
    static final ABNF obsDay = REG.rule("obs-day", "[CFWS] 1*2DIGIT [CFWS]");
    static final ABNF obsYear = REG.rule("obs-year", "[CFWS] 2*DIGIT [CFWS]");
    static final ABNF obsHour = REG.rule("obs-hour", "[CFWS] 2DIGIT [CFWS]");
    static final ABNF obsMinute = REG.rule("obs-minute", "[CFWS] 2DIGIT [CFWS]");
    static final ABNF obsSecond = REG.rule("obs-second", "[CFWS] 2DIGIT [CFWS]");
    static final ABNF obsZone = REG.rule("obs-zone", "\"UT\" / \"GMT\" / \"EST\" / \"EDT\" / \"CST\" / \"CDT\" / "
            + "\"MST\" / \"MDT\" / \"PST\" / \"PDT\" / %d65-73 / %d75-90 / %d97-105 / %d107-122");
    // 4.5. Obsolete Header Fields
    static final ABNF obsFields = REG.rule("obs-fields", "*(obs-return /"
            + " obs-received /"
            + " obs-orig-date /"
            + " obs-from /"
            + " obs-sender /"
            + " obs-reply-to /"
            + " obs-to /"
            + " obs-cc /"
            + " obs-bcc /"
            + " obs-message-id /"
            + " obs-in-reply-to /"
            + " obs-references /"
            + " obs-subject /"
            + " obs-comments /"
            + " obs-keywords /"
            + " obs-resent-date /"
            + " obs-resent-from /"
            + " obs-resent-send /"
            + " obs-resent-rply /"
            + " obs-resent-to /"
            + " obs-resent-cc /"
            + " obs-resent-bcc /"
            + " obs-resent-mid /"
            + " obs-optional)");
    // 4.5.1.
    static final ABNF obsOrigDate = REG.rule("obs-orig-date", "\"Date\" *WSP \":\" date-time CRLF");
    // 4.5.2.
    static final ABNF obsFrom = REG.rule("obs-from", "\"From\" *WSP \":\" mailbox-list CRLF");
    static final ABNF obsSender = REG.rule("obs-sender", "\"Sender\" *WSP \":\" mailbox CRLF");
    static final ABNF obsReplyTo = REG.rule("obs-reply-to", "\"Reply-To\" *WSP \":\" address-list CRLF");
    // 4.5.3.
    static final ABNF obsTo = REG.rule("obs-to", "\"To\" *WSP \":\" address-list CRLF");
    static final ABNF obsCc = REG.rule("obs-cc", "\"Cc\" *WSP \":\" address-list CRLF");
    static final ABNF obsBcc = REG.rule("obs-bcc", "\"Bcc\" *WSP \":\" (address-list / (*([CFWS] \",\") [CFWS])) CRLF");
    // 4.5.4. Obsolete Identification Fields
    static final ABNF obsMessageId = REG.rule("obs-message-id", "\"Message-ID\" *WSP \":\" msg-id CRLF");
    static final ABNF obsInReplyTo = REG.rule("obs-in-reply-to", "\"In-Reply-To\" *WSP \":\" *(phrase / msg-id) CRLF");
    static final ABNF obsReferences = REG.rule("obs-references", "\"References\" *WSP \":\" *(phrase / msg-id) CRLF");
    static final ABNF obsIdLeft = REG.rule("obs-id-left", localPart);
    static final ABNF obsIdRight = REG.rule("obs-id-right", domain);
    // 4.5.5. Obsolete Informational FIelds
    static final ABNF obsSubject = REG.rule("obs-subject", "\"Subject\" *WSP \":\" unstructired CRLF");
    static final ABNF obsComments = REG.rule("obs-comments", "\"Comments\" *WSP \":\" unstructured CRLF");
    static final ABNF obsKeywords = REG.rule("obs-keywords", "\"Keywords\" *WSP \":\" obs-phrase-list CRLF");
    // 4.5.6. Obsolete Resent Fields
    static final ABNF obsResentFrom = REG.rule("obs-resent-from", "\"Resent-From\" *WSP \":\" mailbox-list CRLF");
    static final ABNF obsResentSend = REG.rule("obs-resent-send", "\"Resent-Sender\" *WSP \":\" mailbox CRLF");
    static final ABNF obsResentDate = REG.rule("obs-resent-date", "\"Resent-Date\" *WSP \":\" date-time CRLF");
    static final ABNF obsResentTo = REG.rule("obs-resent-to", "\"Resent-To\" *WSP \":\" address-list CRLF");
    static final ABNF obsResentCc = REG.rule("obs-resent-cc", "\"Resent-Cc\" *WSP \":\" address-list CRLF");
    static final ABNF obsResentBcc = REG.rule("obs-resent-bcc", "\"Resent-Bcc\" *WSP \":\" (address-list / (*([CFWS] \",\") [CFWS])) CRLF");
    static final ABNF obsResentMid = REG.rule("obs-resent-mid", "\"Resent-Message-ID\" *WSP \":\" msg-id CRLF");
    static final ABNF obsResentRply = REG.rule("obs-resent-rply", "\"Resent-Reply-To\" *WSP \":\" address-list CRLF");
    // 4.5.7. Obsolete Trace Fields
    static final ABNF obsReturn = REG.rule("obs-return", "\"Return-Path\" *WSP \":\" path CRLF");
//    static ABNF obsReceived = OBS.rule("obs-received", "\"Received\" *WSP \":\" *received-token CRLF");
    static final ABNF obsReceived = REG.rule("obs-received", "\"Received\" *WSP \":\" [1*received-token / CFWS] CRLF"); // Errata ID: 3979
    // 4.5.8. Obsolete optional fields
    static final ABNF obsOptional = REG.rule("obs-optional", "field-name *WSP \":\" unstructured CRLF");
}
