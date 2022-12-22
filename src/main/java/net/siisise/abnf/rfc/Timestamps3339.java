package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 *
 */
public class Timestamps3339 {

    public static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    static ABNF dateFullyear = REG.rule("date-fullyear", "4DIGIT");
    static ABNF dateMonth = REG.rule("date-month", "2DIGIT"); // ; 01-12
    static ABNF dateMday = REG.rule("date-mday", "2DIGIT"); //

    static ABNF timeHour = REG.rule("time-hour", "2DIGIT"); // 00-23
    static ABNF timeMinute = REG.rule("time-minute", "2DIGIT");
    static ABNF timeSecond = REG.rule("time-second", "2DIGIT");

    static ABNF timeSecfrac = REG.rule("time-secfrac", "\".\" 1*DIGIT");
    static ABNF timeNumoffset = REG.rule("time-numoffset", "(\"+\" / \"-\") time-hour \":\" time-minute");
    static ABNF timeOffset = REG.rule("time-offset", "\"Z\" / time-numoffset");

    static ABNF partialTime = REG.rule("partial-time", "time-hour \":\" time-minute \":\" time-second [time-secfrac]");
    static ABNF fullDate = REG.rule("full-date", "date-fullyear \"-\" date-month \"-\" date-mday");
    static ABNF fullTime = REG.rule("full-time", "partial-time time-offset");

    static ABNF dateTime = REG.rule("date-time", "full-date \"T\" full-time");

    // Appendix A. ISO 8601 Collected ABNF
    public static class ISO8601 {

        static ABNFReg REG = new ABNFReg(ABNF5234.BASE);

        static ABNF dateCentury = REG.rule("date-century", "2DIGIT");
        static ABNF dateDecade = REG.rule("date-decade", ABNF5234.DIGIT);
        static ABNF dateSubdecade = REG.rule("date-subdecade", ABNF5234.DIGIT);
        static ABNF dateYear = REG.rule("date-year", "date-decade date-subdecade");
        static ABNF dateFullyear = REG.rule("date-fullyear", "date-century date-year");
        static ABNF dateMonth = REG.rule("date-month", "2DIGIT");
        static ABNF dateWday = REG.rule("date-wday", "DIGIT"); // 1-7
        static ABNF dateMday = REG.rule("date-mday", "2DIGIT");
        static ABNF dateYday = REG.rule("date-yday", "3DIGIT");
        static ABNF dateWeek = REG.rule("date-week", "2DIGIT");

        static ABNF datepartFullyear = REG.rule("datepart-fullyear", "[date-century] date-year [\"-\"]");
        static ABNF datepartPtyear = REG.rule("datepart-ptyear", "\"-\" [date-subdecade [\"-\"]]");
        static ABNF datepartWkyear = REG.rule("datepart-wkyear", "datepart-ptyear / datepart-fullyear");

        static ABNF dateoptCentury = REG.rule("dateopt-century", "\"-\" / date-century");
        static ABNF dateoptFullyear = REG.rule("dateopt-fullyear", "\"-\" / datepart-fullyear");
        static ABNF dateoptYear = REG.rule("dateopt-year", "\"-\" / (date-year [\"-\"])");
        static ABNF dateoptMonth = REG.rule("dateopt-month", "\"-\" / (date-month [\"-\"])");
        static ABNF dateoptWeek = REG.rule("dateopt-week", "\"-\" / (date-week [\"-\"])");

        static ABNF datespecFull = REG.rule("datespec-full", "datepart-fullyear date-month [\"-\"] date-mday");
        static ABNF datespecYear = REG.rule("datespec-year", "date-century / dateopt-century date-year");
        static ABNF datespecMonth = REG.rule("datespec-month", "\"-\" dateopt-year date-month [[\"-\"] date-mday]");
        static ABNF datespecMday = REG.rule("datespec-mday", "\"--\" dateopt-month date-mday");
        static ABNF datespecWeek = REG.rule("datespec-week", "datepart-wkyear \"W\" (date-week / dateopt-week date-wday)");
        static ABNF datespecWday = REG.rule("datespec-wday", "\"---\" date-wday");
        static ABNF datespecYday = REG.rule("datespec-yday", "dateopt-fullyear date-yday");

        static ABNF date = REG.rule("date", datespecFull.or(datespecYear, datespecMonth,
                datespecMday, datespecWeek, datespecWday, datespecYday));

        // Time:
        static ABNF timeHour = REG.rule("time-hour", "2DIGIT");
        static ABNF timeMinute = REG.rule("time-minute", "2DIGIT");
        static ABNF timeSecond = REG.rule("time-second", "2DIGIT");
        static ABNF timeFraction = REG.rule("time-fraction", "(\",\" . \".\") 1*DIGIT");
        static ABNF timeNumoffset = REG.rule("time-numoffset", "(\"+\" / \"-\") time-hour [[\":\"] time-minute]");
        static ABNF timeZone = REG.rule("time-zone", "\"Z\" / time-numoffset");

        static ABNF timeoptHour = REG.rule("timeopt-hour", "\"-\" / (time-hour [\":\"])");
        static ABNF timeoptMinute = REG.rule("timeopt-minute", "\"-\" / (time-minute [\":\"])");

        static ABNF timespecHour = REG.rule("timespec-hour", "time-hour [[\":\"] time-minute [[\":\"] time-second]]");
        static ABNF timespecMinute = REG.rule("timespec-minute", "timeopt-hour time-minute [[\":\"] time-second]");
        static ABNF timespecSecond = REG.rule("timespec-second", "\"-\" timeopt-minute time-second");
        static ABNF timespecMidnight = REG.rule("timespec-midnight", "\"24\" [[\":\"] \"00\" [[\":\"] \"00\"]]");
        static ABNF timespecBase = REG.rule("timespec-base", timespecHour.or(timespecMinute, timespecSecond, timespecMidnight));

        static ABNF time = REG.rule("time", "timespec-base [time-fraction] [time-zone]");

        static ABNF isoDateTime = REG.rule("iso-date-time", "date \"T\" time");

        // Durations:
        static ABNF durSecond = REG.rule("dur-second", "1*DIGIT \"S\"");
        static ABNF durMinute = REG.rule("dur-minute", "1*DIGIT \"M\" [dur-second]");
        static ABNF durHour = REG.rule("dur-hour", "1*DIGIT \"H\" [dur-minute]");
        static ABNF durTime = REG.rule("dur-time", "\"T\" (dur-hour / dur-minute / dur-second)");
        static ABNF durDay = REG.rule("dur-day", "1*DIGIT \"D\"");
        static ABNF durWeek = REG.rule("dur-week", "1*DIGIT \"W\"");
        static ABNF durMonth = REG.rule("dur-month", "1*DIGIT \"M\" [dur-day]");
        static ABNF durYear = REG.rule("dur-year", "1*DIGIT \"Y\" [dur-month]");
        static ABNF durDate = REG.rule("dur-date", "(dur-day / dur-month / dur-year) [dur-time]");

        static ABNF duration = REG.rule("duration", "\"P\" (dur-date / dur-time / dur-week)");

        // Periods:
        static ABNF periodExplicit = REG.rule("period-explicit", "iso-date-time \"/\" iso-date-time");
        static ABNF periodStart = REG.rule("period-start", "iso-date-time \"/\" duration");
        static ABNF periodEnd = REG.rule("period-end", "duration \"/\" iso-date-time");

        static ABNF period = REG.rule("period", periodExplicit.or(periodStart, periodEnd));
    }
}
