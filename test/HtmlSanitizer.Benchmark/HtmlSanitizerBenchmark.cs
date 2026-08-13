using BenchmarkDotNet.Attributes;

namespace Ganss.Xss.Benchmark;

[MemoryDiagnoser]
public class HtmlSanitizerBenchmark
{
    private HtmlSanitizer _sanitizer = null!;
    private HtmlSanitizer _styleSheetSanitizer = null!;
    private string _googleFileContent = null!;
    private string _largeFileContent = null!;
    private string _emailFileContent = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _googleFileContent = File.ReadAllText("google.html");
        _largeFileContent = File.ReadAllText("ecmascript.html");
        _emailFileContent = File.ReadAllText("email.html");
        _sanitizer = new HtmlSanitizer();

        // <style> is not an allowed tag by default, so the tag is dropped before its content is
        // ever looked at. Allowing it is what puts SanitizeStyleSheets - and the CSS parsing and
        // regex work behind it - on the measured path.
        _styleSheetSanitizer = new HtmlSanitizer();
        _styleSheetSanitizer.AllowedTags.Add("style");
    }

    /// <summary>
    /// Small content produced by for example Orchard, nothing to sanitize.
    /// </summary>
    [Benchmark]
    public void SanitizeSmall()
    {
        _sanitizer.Sanitize("<p>Never in all their history have men been able truly to conceive of the world as one: a single sphere, a globe, having the qualities of a globe, a round earth in which all the directions eventually meet, in which there is no center because every point, or none, is center — an equal earth which all men occupy as equals. The airman's earth, if free men make it, will be truly round: a globe in practice, not in theory.</p>\n<p>Science cuts two ways, of course; its products can be used for both good and evil. But there's no turning back from science. The early warnings about technological dangers also come from science.</p>\n<p>What was most significant about the lunar voyage was not that man set foot on the Moon but that they set eye on the earth.</p>\n<p>A Chinese tale tells of some men sent to harm a young girl who, upon seeing her beauty, become her protectors rather than her violators. That's how I felt seeing the Earth for the first time. I could not help but love and cherish her.</p>\n<p>For those who have seen the Earth from space, and for the hundreds and perhaps thousands more who will, the experience most certainly changes your perspective. The things that we share in our world are far more valuable than those which divide us.</p>\n");
    }

    /// <summary>
    /// Google is script-heavy.
    /// </summary>
    [Benchmark]
    public void SanitizeGoogle()
    {
        _sanitizer.Sanitize(_googleFileContent);
    }

    /// <summary>
    /// Partial ECMAScript is DOM-heavy.
    /// </summary>
    [Benchmark]
    public void SanitizeLarge()
    {
        _sanitizer.Sanitize(_largeFileContent);
    }

    /// <summary>
    /// A newsletter is style-heavy: the work is CSS rather than DOM.
    /// </summary>
    /// <remarks>
    /// The other documents leave the CSS path almost unmeasured - ECMAScript has no styled element
    /// at all and Google has eight of 309 - even though sanitizing a style attribute costs far more
    /// per byte than sanitizing ordinary markup. HTML email is where that case really arises, since
    /// mail clients strip stylesheets and templates inline everything instead.
    /// <para>
    /// email.html is generated rather than taken from a real campaign, so that nothing
    /// third-party is vendored in, but its shape is calibrated against a real responsive template
    /// (Cerberus): about 45% of elements carry a style attribute, averaging 3.3 declarations each,
    /// drawn from the property mix that template actually uses - margin, font-size, line-height,
    /// color, padding, font-family. Values differ per element on purpose; repeating one string
    /// would let the CSS parser cache its way to a number no real document would produce. A
    /// minority carry background-image: url(...), which is kept a minority because the reference
    /// template has none inline, and over-representing it would flatter any change aimed at URL
    /// handling.
    /// </para>
    /// </remarks>
    [Benchmark]
    public void SanitizeEmail()
    {
        _sanitizer.Sanitize(_emailFileContent);
    }

    /// <summary>
    /// The same newsletter with stylesheets kept, which is what exercises SanitizeStyleSheets.
    /// </summary>
    [Benchmark]
    public void SanitizeEmailWithStyleSheets()
    {
        _styleSheetSanitizer.Sanitize(_emailFileContent);
    }
}
