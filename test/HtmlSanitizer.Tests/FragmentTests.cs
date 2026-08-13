using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Parser;
using Xunit;

namespace Ganss.Xss.Tests;

/// <summary>
/// Tests for <see cref="HtmlSanitizer.SanitizeFragment(string, string, string, AngleSharp.IMarkupFormatter)"/>
/// and its <see cref="IElement"/> overload, which parse a fragment in the context of the element it
/// will be inserted into rather than in &lt;body&gt;.
/// </summary>
/// <remarks>
/// Part of <see cref="HtmlSanitizerTests"/> rather than a class of its own so these tests stay in the
/// set <see cref="HtmlSanitizerTests.ThreadTest"/> reflects over, which is what exercises them
/// concurrently.
/// </remarks>
public partial class HtmlSanitizerTests
{
    // The case from the issue: parsing in body context drops a lone th, because a th is only valid
    // deeper in the tree. Naming the context it is destined for keeps it.
    [Fact]
    public void SanitizeFragmentKeepsTagValidOnlyInContextTest()
    {
        var sanitizer = new HtmlSanitizer();

        Assert.Equal("Header", sanitizer.Sanitize(@"<th>Header</th>"));
        Assert.Equal(@"<th>Header</th>", sanitizer.SanitizeFragment(@"<th>Header</th>", "tr"));
    }

    [Theory]
    [InlineData("tr", @"<th>Header</th>", @"<th>Header</th>")]
    [InlineData("tr", @"<td>a</td><td>b</td>", @"<td>a</td><td>b</td>")]
    [InlineData("table", @"<tr><td>x</td></tr>", @"<tbody><tr><td>x</td></tr></tbody>")]
    [InlineData("tbody", @"<tr><td>x</td></tr>", @"<tr><td>x</td></tr>")]
    [InlineData("ul", @"<li>a</li><li>b</li>", @"<li>a</li><li>b</li>")]
    [InlineData("dl", @"<dt>a</dt><dd>b</dd>", @"<dt>a</dt><dd>b</dd>")]
    [InlineData("select", @"<option>a</option>", @"<option>a</option>")]
    [InlineData("optgroup", @"<option>a</option>", @"<option>a</option>")]
    [InlineData("colgroup", @"<col span=""2"">", @"<col span=""2"">")]
    [InlineData("td", @"<b>x</b>", @"<b>x</b>")]
    public void SanitizeFragmentUsesContextInsertionModeTest(string context, string html, string expected)
    {
        Assert.Equal(expected, new HtmlSanitizer().SanitizeFragment(html, context));
    }

    // A context that does not change the insertion mode has to behave exactly like Sanitize.
    [Theory]
    [InlineData("div")]
    [InlineData("span")]
    [InlineData("body")]
    public void SanitizeFragmentInBodyLikeContextMatchesSanitizeTest(string context)
    {
        var sanitizer = new HtmlSanitizer();
        const string Html = @"<p onclick=""alert(1)"">a</p><script>alert(2)</script><b>c</b>";

        Assert.Equal(sanitizer.Sanitize(Html), sanitizer.SanitizeFragment(Html, context));
    }

    // Every stage of the pipeline has to keep running once the parse happens in a context.
    [Theory]
    [InlineData("tr", @"<th onclick=""alert(1)"">H</th>", @"<th>H</th>")]
    [InlineData("tr", @"<th><script>alert(1)</script>H</th>", @"<th>H</th>")]
    [InlineData("tr", @"<td><a href=""javascript:alert(1)"">x</a></td>", @"<td><a>x</a></td>")]
    [InlineData("tr", @"<td><!-- c -->x</td>", @"<td>x</td>")]
    [InlineData("td", @"<img src=""x"" onerror=""alert(1)"">", @"<img src=""x"">")]
    [InlineData("ul", @"<li onmouseover=""alert(1)"">a</li>", @"<li>a</li>")]
    [InlineData("select", @"<option onfocus=""alert(1)"">a</option>", @"<option>a</option>")]
    public void SanitizeFragmentRemovesDisallowedContentTest(string context, string html, string expected)
    {
        Assert.Equal(expected, new HtmlSanitizer().SanitizeFragment(html, context));
    }

    [Fact]
    public void SanitizeFragmentSanitizesStyleAttributeTest()
    {
        var actual = new HtmlSanitizer().SanitizeFragment(
            @"<td style=""color: red; behavior: url(x)"">x</td>", "tr");

        Assert.Contains("color", actual, StringComparison.Ordinal);
        Assert.DoesNotContain("behavior", actual, StringComparison.Ordinal);
    }

    // A fragment is parsed into a subtree detached from the document, which the document's own
    // stylesheet list and descendants both miss, so sanitizing has to search from the fragment.
    [Fact]
    public void SanitizeFragmentSanitizesStyleSheetTest()
    {
        var sanitizer = new HtmlSanitizer();
        sanitizer.AllowedTags.Add("style");

        var actual = sanitizer.SanitizeFragment(
            @"<td><style>a { color: red; behavior: url(x) }</style>x</td>", "tr");

        Assert.Contains("color", actual, StringComparison.Ordinal);
        Assert.DoesNotContain("behavior", actual, StringComparison.Ordinal);
    }

    // A <style type=""> yields no stylesheet from the CSS object model and is covered by a re-parse
    // fallback; that fallback searches from the same node, so it needs the fragment too.
    [Fact]
    public void SanitizeFragmentSanitizesTypelessStyleSheetTest()
    {
        var sanitizer = new HtmlSanitizer();
        sanitizer.AllowedTags.Add("style");
        sanitizer.AllowedAttributes.Add("type");

        var actual = sanitizer.SanitizeFragment(
            @"<td><style type="""">a { behavior: url(x) }</style>x</td>", "tr");

        Assert.DoesNotContain("behavior", actual, StringComparison.Ordinal);
    }

    // Building the context element needs a parser and so does parsing the fragment, but a caller's
    // factory is not obliged to return the same one twice - it may build a parser per call, or count
    // them. Sanitize asks once, and so must this.
    [Theory]
    [InlineData("tr")]
    [InlineData("style")]
    [InlineData("notatag")]
    public void SanitizeFragmentCallsParserFactoryOnceTest(string context)
    {
        var sanitizer = new HtmlSanitizer();
        var parser = sanitizer.HtmlParserFactory();
        var calls = 0;
        sanitizer.HtmlParserFactory = () => { calls++; return parser; };

        // A rejected context must not have cost more than an accepted one either.
        try { sanitizer.SanitizeFragment(@"<th>H</th>", context); }
        catch (ArgumentException) { }

        Assert.Equal(1, calls);
    }

    [Fact]
    public void SanitizeFragmentWithContextElementCallsParserFactoryOnceTest()
    {
        var sanitizer = new HtmlSanitizer();
        var parser = sanitizer.HtmlParserFactory();
        using var document = parser.ParseDocument(string.Empty);
        var context = document.CreateElement("tr");
        var calls = 0;
        sanitizer.HtmlParserFactory = () => { calls++; return parser; };

        sanitizer.SanitizeFragment(@"<th>H</th>", context);

        Assert.Equal(1, calls);
    }

    // The parser handed on from the tag-name overload has to be the one that parses the fragment,
    // since that is what decides the fragment's configuration - a CSS-less one drops styles.
    [Fact]
    public void SanitizeFragmentParsesWithTheFactorysParserTest()
    {
        var sanitizer = new HtmlSanitizer();
        var withoutCss = new HtmlParser(new HtmlParserOptions { IsScripting = true },
            BrowsingContext.New(Configuration.Default));
        sanitizer.HtmlParserFactory = () => withoutCss;

        Assert.Equal(@"<td>x</td>",
            sanitizer.SanitizeFragment(@"<td style=""color: red"">x</td>", "tr"));

        sanitizer.HtmlParserFactory = HtmlSanitizer.DefaultHtmlParserFactory;

        Assert.Equal(@"<td style=""color: rgba(255, 0, 0, 1)"">x</td>",
            sanitizer.SanitizeFragment(@"<td style=""color: red"">x</td>", "tr"));
    }

    [Fact]
    public void SanitizeFragmentResolvesRelativeUrlsAgainstBaseUrlTest()
    {
        var actual = new HtmlSanitizer().SanitizeFragment(
            @"<td><img src=""a.png""></td>", "tr", "https://www.example.com/x/");

        Assert.Equal(@"<td><img src=""https://www.example.com/x/a.png""></td>", actual);
    }

    [Fact]
    public void SanitizeFragmentUsesSuppliedOutputFormatterTest()
    {
        var sanitizer = new HtmlSanitizer();

        Assert.Equal(@"<td><img src=""x""></td>",
            sanitizer.SanitizeFragment(@"<td><img src=""x""></td>", "tr"));
        Assert.Equal(@"<td><img src=""x"" /></td>",
            sanitizer.SanitizeFragment(@"<td><img src=""x""></td>", "tr", "",
                AngleSharp.Xhtml.XhtmlMarkupFormatter.Instance));
    }

    [Fact]
    public void SanitizeFragmentRaisesEventsTest()
    {
        var sanitizer = new HtmlSanitizer();
        var removedTag = false;
        var removedAttribute = false;
        var postProcessedDom = false;
        var postProcessedNode = false;

        sanitizer.RemovingTag += (_, _) => removedTag = true;
        sanitizer.RemovingAttribute += (_, _) => removedAttribute = true;
        sanitizer.PostProcessDom += (_, _) => postProcessedDom = true;
        sanitizer.PostProcessNode += (_, _) => postProcessedNode = true;

        sanitizer.SanitizeFragment(@"<th onclick=""alert(1)""><script>x</script>H</th>", "tr");

        Assert.True(removedTag);
        Assert.True(removedAttribute);
        Assert.True(postProcessedDom);
        Assert.True(postProcessedNode);
    }

    // Sanitizing the output again in the same context must not change it, or the markup handed back
    // would not be the markup that was screened.
    [Theory]
    [InlineData("tr", @"<th>H</th>")]
    [InlineData("tr", @"<td>a</td>b<td>c</td>")]
    [InlineData("table", @"<tr><td>x</td></tr>")]
    [InlineData("ul", @"<li>a</li>")]
    [InlineData("select", @"<option>a</option>")]
    [InlineData("colgroup", @"<col span=""2"">")]
    public void SanitizeFragmentIsIdempotentTest(string context, string html)
    {
        var sanitizer = new HtmlSanitizer();

        var once = sanitizer.SanitizeFragment(html, context);

        Assert.Equal(once, sanitizer.SanitizeFragment(once, context));
    }

    // In these contexts the parser yields a single text node, so nothing is left to sanitize and
    // nothing is escaped on the way out - the input would come back verbatim.
    [Theory]
    [InlineData("style")]
    [InlineData("script")]
    [InlineData("xmp")]
    [InlineData("iframe")]
    [InlineData("noembed")]
    [InlineData("noframes")]
    public void SanitizeFragmentRejectsRawTextContextTest(string context)
    {
        var sanitizer = new HtmlSanitizer();

        var ex = Assert.Throws<ArgumentException>(() =>
            sanitizer.SanitizeFragment(@"<img src=""x"" onerror=""alert(1)"">", context));

        Assert.Equal("context", ex.ParamName);
    }

    // The IElement overload takes the same input straight from the caller, so it needs the guard too.
    [Fact]
    public void SanitizeFragmentRejectsRawTextContextElementTest()
    {
        var sanitizer = new HtmlSanitizer();
        using var document = sanitizer.HtmlParserFactory().ParseDocument(string.Empty);
        var context = document.CreateElement("style");

        var ex = Assert.Throws<ArgumentException>(() =>
            sanitizer.SanitizeFragment(@"</style><img src=""x"" onerror=""alert(1)"">", context));

        Assert.Equal("context", ex.ParamName);
    }

    // A misspelled context would otherwise fall back to body behaviour and silently do the wrong thing.
    [Theory]
    [InlineData("notatag")]
    [InlineData("tbdoy")]
    public void SanitizeFragmentRejectsUnknownContextTest(string context)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new HtmlSanitizer().SanitizeFragment(@"<th>H</th>", context));

        Assert.Equal("context", ex.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a b")]
    public void SanitizeFragmentRejectsMalformedContextNameTest(string context)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new HtmlSanitizer().SanitizeFragment(@"<th>H</th>", context));

        Assert.Equal("context", ex.ParamName);
    }

    [Fact]
    public void SanitizeFragmentRejectsNullArgumentsTest()
    {
        var sanitizer = new HtmlSanitizer();
        using var document = sanitizer.HtmlParserFactory().ParseDocument(string.Empty);

        Assert.Throws<ArgumentNullException>(() => sanitizer.SanitizeFragment(null!, "tr"));
        Assert.Throws<ArgumentNullException>(() => sanitizer.SanitizeFragment("x", (string)null!));
        Assert.Throws<ArgumentNullException>(() => sanitizer.SanitizeFragment("x", (IElement)null!));
        Assert.Throws<ArgumentNullException>(() => sanitizer.SanitizeFragment(null!, document.CreateElement("tr")));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("<!-- c -->", "")]
    public void SanitizeFragmentWithNothingToKeepReturnsEmptyTest(string html, string expected)
    {
        Assert.Equal(expected, new HtmlSanitizer().SanitizeFragment(html, "tr"));
    }

    // The context only selects an insertion mode; AngleSharp clones it, so the caller's element is
    // untouched and can be used again.
    [Fact]
    public void SanitizeFragmentDoesNotMutateContextElementTest()
    {
        var sanitizer = new HtmlSanitizer();
        using var document = sanitizer.HtmlParserFactory().ParseDocument(string.Empty);
        var context = document.CreateElement("tr");

        Assert.Equal(@"<th>A</th>", sanitizer.SanitizeFragment(@"<th>A</th>", context));
        Assert.Equal(@"<th>B</th>", sanitizer.SanitizeFragment(@"<th>B</th>", context));
        Assert.Equal(0, context.ChildNodes.Length);
    }

    // A tag name can only ever name an HTML element, so foreign content needs the element overload.
    [Fact]
    public void SanitizeFragmentAcceptsForeignContentContextTest()
    {
        var sanitizer = new HtmlSanitizer();
        sanitizer.AllowedTags.Add("text");
        using var document = sanitizer.HtmlParserFactory().ParseDocument(string.Empty);
        var context = document.CreateElement(NamespaceNames.SvgUri, "svg");

        var actual = sanitizer.SanitizeFragment(@"<text onclick=""alert(1)"">hi</text>", context);

        Assert.Equal(@"<text>hi</text>", actual);
    }

    [Fact]
    public void SanitizeFragmentIsExposedOnInterfaceTest()
    {
        IHtmlSanitizer sanitizer = new HtmlSanitizer();
        using var document = new HtmlSanitizer().HtmlParserFactory().ParseDocument(string.Empty);

        Assert.Equal(@"<th>H</th>", sanitizer.SanitizeFragment(@"<th>H</th>", "tr"));
        Assert.Equal(@"<th>H</th>", sanitizer.SanitizeFragment(@"<th>H</th>", document.CreateElement("tr")));
    }
}
