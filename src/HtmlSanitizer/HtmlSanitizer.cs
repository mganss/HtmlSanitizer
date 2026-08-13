using AngleSharp;
using AngleSharp.Css;
using AngleSharp.Css.Dom;
using AngleSharp.Css.Parser;
using AngleSharp.Css.Values;
using AngleSharp.Dom;
using AngleSharp.Html;
using AngleSharp.Html.Dom;
using AngleSharp.Html.Parser;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Ganss.Xss;

/// <summary>
/// Cleans HTML documents and fragments from constructs that can lead to <a href="https://en.wikipedia.org/wiki/Cross-site_scripting">XSS attacks</a>.
/// </summary>
/// <remarks>
/// XSS attacks can occur at several levels within an HTML document or fragment:
/// <list type="bullet">
/// <item>HTML tags (e.g. the &lt;script&gt; tag)</item>
/// <item>HTML attributes (e.g. the "onload" attribute)</item>
/// <item>CSS styles (url property values)</item>
/// <item>malformed HTML or HTML that exploits parser bugs in specific browsers</item>
/// </list>
/// <para>
/// The HtmlSanitizer class addresses all of these possible attack vectors by using a sophisticated HTML parser (<a href="https://github.com/AngleSharp/AngleSharp">AngleSharp</a>).
/// </para>
/// <para>
/// In order to facilitate different use cases, HtmlSanitizer can be customized at the levels mentioned above:
/// <list type="bullet">
/// <item>You can specify the allowed HTML tags through the property <see cref="AllowedTags"/>. All other tags will be stripped.</item>
/// <item>You can specify the allowed HTML attributes through the property <see cref="AllowedAttributes"/>. All other attributes will be stripped.</item>
/// <item>You can specify the allowed CSS property names through the property <see cref="AllowedCssProperties"/>. All other styles will be stripped.</item>
/// <item>You can specify the allowed URI schemes through the property <see cref="AllowedSchemes"/>. All other URIs will be stripped.</item>
/// <item>You can specify the HTML attributes that contain URIs (such as "src", "href" etc.) through the property <see cref="UriAttributes"/>.</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// <![CDATA[
/// var sanitizer = new HtmlSanitizer();
/// var html = @"<script>alert('xss')</script><div onload=""alert('xss')"" style=""background-color: test"">Test<img src=""test.gif"" style=""background-image: url(javascript:alert('xss')); margin: 10px""></div>";
/// var sanitized = sanitizer.Sanitize(html, "http://www.example.com");
/// // -> "<div style="background-color: test">Test<img style="margin: 10px" src="http://www.example.com/test.gif"></div>"
/// ]]>
/// </code>
/// </example>
public class HtmlSanitizer : IHtmlSanitizer
{
    private const string StyleAttributeName = "style";
    private const string StyleTagName = "style";
    private const string SrcdocAttributeName = "srcdoc";
    private const string SrcsetAttributeName = "srcset";

    /// <summary>
    /// How many levels of nested srcdoc documents are sanitized before the attribute is dropped.
    /// Each level costs a full parse, and legitimate markup does not nest browsing contexts this
    /// deeply, so the limit only bounds the work a hostile input can force.
    /// </summary>
    private const int MaxSrcdocDepth = 5;

    // from http://genshi.edgewall.org/
    private static readonly Regex CssUnicodeEscapes = new(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
    private static readonly Regex CssComments = new(@"/\*.*?\*/", RegexOptions.Compiled);
    // IE6 <http://heideri.ch/jso/#80>
    private static readonly Regex CssExpression = new(@"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);
    // Whitespace is allowed around the parenthesis and around the quotes, as a browser tokenizing
    // url() would. The whitespace runs are atomic so the pattern can't backtrack into them, which
    // is what made the earlier permissive version vulnerable to ReDoS (see 7fb4f86).
    private static readonly Regex CssUrl = new(@"[Uu][Rr\u0280][Ll\u029F](?>\s*)\((?>\s*)(['""]?)([^'"")]*)(['""]?)(?>\s*)\)?", RegexOptions.Compiled);
    private static readonly Regex WhitespaceRegex = new(@"\s+", RegexOptions.Compiled);
    private static readonly CssParserOptions cssParserOptions = new()
    {
        IsIncludingUnknownDeclarations = true,
        IsIncludingUnknownRules = true,
        IsToleratingInvalidSelectors = true,
    };

    private static readonly IConfiguration defaultConfiguration = Configuration.Default.WithCss(cssParserOptions);

    private static readonly HtmlParser defaultHtmlParser = new(new HtmlParserOptions { IsScripting = true }, BrowsingContext.New(defaultConfiguration));

    // Used to relate longhand properties back to the shorthands they belong to. Only the property
    // metadata is needed, so the default factory is enough regardless of the browsing context.
    private static readonly DefaultDeclarationFactory declarationFactory = new();
    private static readonly ConcurrentDictionary<string, string[]> shorthandsOf = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, HashSet<string>> longhandsOf = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="HtmlSanitizer"/> class
    /// with the default options.
    /// </summary>
    public HtmlSanitizer()
    {
        AllowedTags = new HashSet<string>(HtmlSanitizerDefaults.AllowedTags, StringComparer.OrdinalIgnoreCase);
        AllowedSchemes = new HashSet<string>(HtmlSanitizerDefaults.AllowedSchemes, StringComparer.OrdinalIgnoreCase);
        AllowedAttributes = new HashSet<string>(HtmlSanitizerDefaults.AllowedAttributes, StringComparer.OrdinalIgnoreCase);
        UriAttributes = new HashSet<string>(HtmlSanitizerDefaults.UriAttributes, StringComparer.OrdinalIgnoreCase);
        UriListAttributes = new HashSet<string>(HtmlSanitizerDefaults.UriListAttributes, StringComparer.OrdinalIgnoreCase);
        AllowedCssProperties = new HashSet<string>(HtmlSanitizerDefaults.AllowedCssProperties, StringComparer.OrdinalIgnoreCase);
        AllowedAtRules = new HashSet<CssRuleType>(HtmlSanitizerDefaults.AllowedAtRules);
        AllowedClasses = new HashSet<string>(HtmlSanitizerDefaults.AllowedClasses);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HtmlSanitizer"/> class
    /// with the given options.
    /// </summary>
    /// <param name="options">Options to control the sanitizing.</param>
    /// <remarks>
    /// Unlike the parameterless constructor, this replaces every collection with the one from
    /// <paramref name="options"/> rather than merging with <see cref="HtmlSanitizerDefaults"/>. See
    /// the remarks on <see cref="HtmlSanitizerOptions"/> and <see cref="HtmlSanitizerOptions.CreateDefault"/>.
    /// </remarks>
    public HtmlSanitizer(HtmlSanitizerOptions options)
    {
        AllowedTags = new HashSet<string>(options.AllowedTags, StringComparer.OrdinalIgnoreCase);
        AllowedSchemes = new HashSet<string>(options.AllowedSchemes, StringComparer.OrdinalIgnoreCase);
        AllowedAttributes = new HashSet<string>(options.AllowedAttributes, StringComparer.OrdinalIgnoreCase);
        UriAttributes = new HashSet<string>(options.UriAttributes, StringComparer.OrdinalIgnoreCase);
        UriListAttributes = new HashSet<string>(options.UriListAttributes, StringComparer.OrdinalIgnoreCase);
        AllowedClasses = new HashSet<string>(options.AllowedCssClasses, StringComparer.OrdinalIgnoreCase);
        AllowedCssProperties = new HashSet<string>(options.AllowedCssProperties, StringComparer.OrdinalIgnoreCase);
        AllowedAtRules = new HashSet<CssRuleType>(options.AllowedAtRules);
        AllowCssCustomProperties = options.AllowCssCustomProperties;
        AllowDataAttributes = options.AllowDataAttributes;
    }

    /// <summary>
    /// Gets or sets the default <see cref="Action{IComment}"/> method that encodes comments.
    /// </summary>
    public Action<IComment> EncodeComment { get; set; } = DefaultEncodeComment;

    /// <summary>
    /// Gets or sets the default <see cref="Action{IElement}"/> method that encodes literal text content.
    /// </summary>
    public Action<IElement> EncodeLiteralTextElementContent { get; set; } = DefaultEncodeLiteralTextElementContent;

    /// <summary>
    /// Gets or sets the default value indicating whether to keep child nodes of elements that are removed. Default is false.
    /// </summary>
    public static bool DefaultKeepChildNodes { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether to keep child nodes of elements that are removed. Default is <see cref="DefaultKeepChildNodes"/>.
    /// </summary>
    public bool KeepChildNodes { get; set; } = DefaultKeepChildNodes;

    /// <summary>
    /// Gets or sets the default <see cref="Func{HtmlParser}"/> object that creates the parser used for parsing the input.
    /// </summary>
    public static Func<HtmlParser> DefaultHtmlParserFactory { get; set; } = () => defaultHtmlParser;

    /// <summary>
    /// Gets or sets the <see cref="Func{HtmlParser}"/> object the creates the parser used for parsing the input.
    /// </summary>
    public Func<HtmlParser> HtmlParserFactory { get; set; } = DefaultHtmlParserFactory;

    /// <summary>
    /// Gets or sets the default <see cref="IMarkupFormatter"/> object used for generating output. Default is <see cref="HtmlFormatter.Instance"/>.
    /// </summary>
    public static IMarkupFormatter DefaultOutputFormatter { get; set; } = HtmlFormatter.Instance;

    /// <summary>
    /// Gets or sets the <see cref="IMarkupFormatter"/> object used for generating output. Default is <see cref="DefaultOutputFormatter"/>.
    /// </summary>
    public IMarkupFormatter OutputFormatter { get; set; } = DefaultOutputFormatter;

    /// <summary>
    /// Gets or sets the default <see cref="IStyleFormatter"/> object used for generating CSS output. Default is <see cref="CssStyleFormatter.Instance"/>.
    /// </summary>
    public static IStyleFormatter DefaultStyleFormatter { get; set; } = CssStyleFormatter.Instance;

    /// <summary>
    /// Gets or sets the <see cref="IStyleFormatter"/> object used for generating CSS output. Default is <see cref="DefaultStyleFormatter"/>.
    /// </summary>
    public IStyleFormatter StyleFormatter { get; set; } = DefaultStyleFormatter;

    /// <summary>
    /// Gets or sets the allowed CSS at-rules such as "@media" and "@font-face".
    /// </summary>
    /// <value>
    /// The allowed CSS at-rules.
    /// </value>
    public ISet<CssRuleType> AllowedAtRules { get; private set; }

    /// <summary>
    /// Gets or sets the allowed URI schemes such as "http" and "https".
    /// </summary>
    /// <value>
    /// The allowed URI schemes.
    /// </value>
    public ISet<string> AllowedSchemes { get; private set; }

    /// <summary>
    /// Gets or sets the allowed HTML tag names such as "a" and "div".
    /// </summary>
    /// <value>
    /// The allowed tag names.
    /// </value>
    public ISet<string> AllowedTags { get; private set; }

    /// <summary>
    /// Gets or sets the allowed HTML attributes such as "href" and "alt".
    /// </summary>
    /// <value>
    /// The allowed HTML attributes.
    /// </value>
    public ISet<string> AllowedAttributes { get; private set; }

    /// <summary>
    /// Allow all HTML5 data attributes; the attributes prefixed with <c>data-</c>.
    /// </summary>
    public bool AllowDataAttributes { get; set; }

    /// <summary>
    /// Gets or sets the HTML attributes that can contain a URI such as "href".
    /// </summary>
    /// <value>
    /// The URI attributes.
    /// </value>
    public ISet<string> UriAttributes { get; private set; }

    /// <summary>
    /// Gets or sets the attributes whose value is a <em>list</em> of URLs rather than a single
    /// one, such as <c>srcset</c> and <c>ping</c>. Each entry is screened against
    /// <see cref="AllowedSchemes"/> on its own and failing entries are dropped; the attribute
    /// itself is removed only when nothing survives.
    /// </summary>
    /// <remarks>
    /// Listing such an attribute in <see cref="UriAttributes"/> instead would screen the whole
    /// value as one URL, which examines only the first entry and lets a hostile one in any later
    /// position through. This set is deliberately separate for that reason.
    /// </remarks>
    public ISet<string> UriListAttributes { get; private set; }

    /// <summary>
    /// Gets or sets the allowed CSS properties such as "font" and "margin".
    /// </summary>
    /// <value>
    /// The allowed CSS properties.
    /// </value>
    public ISet<string> AllowedCssProperties { get; private set; }

    /// <summary>
    /// Allow all custom CSS properties (variables) prefixed with <c>--</c>.
    /// </summary>
    public bool AllowCssCustomProperties { get; set; }

    /// <summary>
    /// Gets or sets a regex that must not match for legal CSS property values.
    /// </summary>
    /// <value>
    /// The regex.
    /// </value>
    public Regex DisallowCssPropertyValue { get; set; } = DefaultDisallowedCssPropertyValue;

    /// <summary>
    /// Gets or sets the allowed CSS classes. If the set is empty, all classes will be allowed.
    /// </summary>
    /// <value>
    /// The allowed CSS classes. An empty set means all classes are allowed.
    /// </value>
    public ISet<string> AllowedClasses { get; private set; }

    /// <summary>
    /// Occurs after sanitizing the document and post processing nodes.
    /// </summary>
    public event EventHandler<PostProcessDomEventArgs>? PostProcessDom;
    /// <summary>
    /// Occurs for every node after sanitizing.
    /// </summary>
    public event EventHandler<PostProcessNodeEventArgs>? PostProcessNode;
    /// <summary>
    /// Occurs before a tag is removed.
    /// </summary>
    public event EventHandler<RemovingTagEventArgs>? RemovingTag;
    /// <summary>
    /// Occurs before an attribute is removed.
    /// </summary>
    public event EventHandler<RemovingAttributeEventArgs>? RemovingAttribute;
    /// <summary>
    /// Occurs before a style is removed.
    /// </summary>
    public event EventHandler<RemovingStyleEventArgs>? RemovingStyle;
    /// <summary>
    /// Occurs before an at-rule is removed.
    /// </summary>
    public event EventHandler<RemovingAtRuleEventArgs>? RemovingAtRule;
    /// <summary>
    /// Occurs before a comment is removed.
    /// </summary>
    public event EventHandler<RemovingCommentEventArgs>? RemovingComment;
    /// <summary>
    /// Occurs before a CSS class is removed.
    /// </summary>
    public event EventHandler<RemovingCssClassEventArgs>? RemovingCssClass;
    /// <summary>
    /// Occurs when a URL is being sanitized.
    /// </summary>
    public event EventHandler<FilterUrlEventArgs>? FilterUrl;
    /// <summary>
    /// Occurs when a CSS rule is being sanitized.
    /// </summary>
    public event EventHandler<FilterCssRuleEventArgs>? FilterCssRule;

    /// <summary>
    /// Raises the <see cref="E:PostProcessDom" /> event.
    /// </summary>
    /// <param name="e">The <see cref="PostProcessDomEventArgs"/> instance containing the event data.</param>
    protected virtual void OnPostProcessDom(PostProcessDomEventArgs e)
    {
        PostProcessDom?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:PostProcessNode" /> event.
    /// </summary>
    /// <param name="e">The <see cref="PostProcessNodeEventArgs"/> instance containing the event data.</param>
    protected virtual void OnPostProcessNode(PostProcessNodeEventArgs e)
    {
        PostProcessNode?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:RemovingTag" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingTagEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingTag(RemovingTagEventArgs e)
    {
        RemovingTag?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:RemovingAttribute" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingAttributeEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingAttribute(RemovingAttributeEventArgs e)
    {
        RemovingAttribute?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:RemovingStyle" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingStyleEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingStyle(RemovingStyleEventArgs e)
    {
        RemovingStyle?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:RemovingAtRule" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingAtRuleEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingAtRule(RemovingAtRuleEventArgs e)
    {
        RemovingAtRule?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:RemovingComment" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingCommentEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingComment(RemovingCommentEventArgs e)
    {
        RemovingComment?.Invoke(this, e);
    }

    /// <summary>
    /// The default regex for disallowed CSS property values.
    /// </summary>
    public static readonly Regex DefaultDisallowedCssPropertyValue = new(@"[<>]", RegexOptions.Compiled);

    /// <summary>
    /// Raises the <see cref="E:RemovingCSSClass" /> event.
    /// </summary>
    /// <param name="e">The <see cref="RemovingCssClassEventArgs"/> instance containing the event data.</param>
    protected virtual void OnRemovingCssClass(RemovingCssClassEventArgs e)
    {
        RemovingCssClass?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:FilterUrl" /> event.
    /// </summary>
    /// <param name="e">The <see cref="FilterUrlEventArgs"/> instance containing the event data.</param>
    protected virtual void OnFilteringUrl(FilterUrlEventArgs e)
    {
        FilterUrl?.Invoke(this, e);
    }

    /// <summary>
    /// Raises the <see cref="E:FilterCssRule" /> event.
    /// </summary>
    /// <param name="e">The <see cref="FilterCssRuleEventArgs"/> instance containing the event data.</param>
    /// <returns>True if the CSS rule should be kept; otherwise, false.</returns>
    protected virtual bool OnFilteringCssRule(FilterCssRuleEventArgs e)
    {
        FilterCssRule?.Invoke(this, e);
        return !e.Cancel;
    }

    /// <summary>
    /// Return all nested subnodes of a node. The nodes are returned in DOM order.
    /// </summary>
    /// <param name="dom">The root node.</param>
    /// <returns>All nested subnodes.</returns>
    private static IEnumerable<INode> GetAllNodes(INode dom)
    {
        if (dom.ChildNodes.Length == 0) yield break;

        var s = new Stack<INode>();
        for (var i = dom.ChildNodes.Length - 1; i >= 0; i--)
        {
            s.Push(dom.ChildNodes[i]);
        }

        while (s.Count > 0)
        {
            var n = s.Pop();
            yield return n;

            for (var i = n.ChildNodes.Length - 1; i >= 0; i--)
            {
                s.Push(n.ChildNodes[i]);
            }
        }
    }

    /// <summary>
    /// Sanitizes the specified HTML body fragment. If a document is given, only the body part will be returned.
    /// </summary>
    /// <param name="html">The HTML body fragment to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
    /// <returns>The sanitized HTML body fragment.</returns>
    public string Sanitize(string html, string baseUrl = "", IMarkupFormatter? outputFormatter = null)
    {
        using var dom = SanitizeDom(html, baseUrl);
        if (dom.Body == null) return string.Empty;
        var output = dom.Body.ChildNodes.ToHtml(outputFormatter ?? OutputFormatter);

        return output;
    }

    /// <summary>
    /// Sanitizes the specified HTML body fragment. If a document is given, only the body part will be returned.
    /// </summary>
    /// <param name="html">The HTML body fragment to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <returns>The sanitized HTML document.</returns>
    public IHtmlDocument SanitizeDom(string html, string baseUrl = "")
    {
        var parser = HtmlParserFactory();
        var dom = parser.ParseDocument("<!doctype html><html><body>" + html);

        if (dom.Body != null)
            DoSanitize(dom, dom.Body, baseUrl);

        return dom;
    }

    /// <summary>
    /// Sanitizes the specified parsed HTML body fragment.
    /// If the document has not been parsed with CSS support then all styles will be removed.
    /// </summary>
    /// <param name="document">The parsed HTML document.</param>
    /// <param name="context">The node within which to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <returns>The sanitized HTML document.</returns>
    public IHtmlDocument SanitizeDom(IHtmlDocument document, IHtmlElement? context = null, string baseUrl = "")
    {
        DoSanitize(document, context ?? (IParentNode)document, baseUrl);

        return document;
    }

    /// <summary>
    /// Sanitizes the specified HTML fragment as if it were being inserted into an element with the
    /// given tag name, rather than into <c>&lt;body&gt;</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="Sanitize(string, string, IMarkupFormatter)"/> always parses in <c>&lt;body&gt;</c>
    /// context, so markup that is only valid deeper in the tree is discarded by the parser before
    /// sanitization ever sees it - <c>&lt;th&gt;Header&lt;/th&gt;</c> becomes the bare text
    /// <c>Header</c>. Naming the context the fragment is destined for keeps that markup intact:
    /// with a context of <c>tr</c> the same input stays <c>&lt;th&gt;Header&lt;/th&gt;</c>.
    /// <para>
    /// The result is only safe in the context it was sanitized for. A fragment sanitized for
    /// <c>tr</c> must be inserted into a <c>tr</c>; putting it in a <c>div</c> instead re-runs the
    /// parser under different rules and can yield a different tree than the one that was screened.
    /// </para>
    /// <para>
    /// A fragment is parsed into a document of its own, which <see cref="PostProcessDom"/> handlers
    /// see in place of the one <see cref="Sanitize(string, string, IMarkupFormatter)"/> gives them -
    /// see the <see cref="SanitizeFragment(string, IElement, string, IMarkupFormatter)"/> overload.
    /// </para>
    /// </remarks>
    /// <param name="html">The HTML fragment to sanitize.</param>
    /// <param name="context">
    /// The tag name of the element the fragment will be inserted into, e.g. "tr" or "ul".
    /// </param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
    /// <returns>The sanitized HTML fragment.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="html"/> or <paramref name="context"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="context"/> is not a known HTML element, or names an element whose content is
    /// raw text - see the <see cref="SanitizeFragment(string, IElement, string, IMarkupFormatter)"/>
    /// overload for why those are rejected.
    /// </exception>
    public string SanitizeFragment(string html, string context, string baseUrl = "", IMarkupFormatter? outputFormatter = null)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var parser = HtmlParserFactory();

        // An element can only be created through a document, so one is parsed here to create it
        // from. The element contributes only its name, which is all the parser reads to pick an
        // insertion mode - the fragment's own configuration comes from the parser that parses it,
        // below. That parser is this one: taking it from the factory a second time would call a
        // caller-supplied factory twice per sanitize, where Sanitize calls it once.
        using var owner = parser.ParseDocument(string.Empty);

        IElement contextElement;

        try
        {
            contextElement = owner.CreateElement(context);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"'{context}' is not a valid element name.", nameof(context), ex);
        }

        if (contextElement is IHtmlUnknownElement)
            throw new ArgumentException($"'{context}' is not a known HTML element.", nameof(context));

        return SanitizeFragment(html, contextElement, baseUrl, outputFormatter, parser);
    }

    /// <summary>
    /// Sanitizes the specified HTML fragment as if it were being inserted into the given element,
    /// rather than into <c>&lt;body&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Takes the context as an element for callers that hold one already. Only its local name is
    /// read: the parser rebuilds the context in the HTML namespace, so an element carries no more
    /// information into the parse than the tag name overload does. The element itself is left
    /// untouched, so a single context element can be reused across calls.
    /// <para>
    /// A context outside the HTML namespace is therefore rejected rather than parsed as if it were
    /// an HTML element of the same name: <c>CreateElement(NamespaceNames.SvgUri, "svg")</c> does not
    /// put the parser into foreign content, and screening a fragment under HTML rules that will be
    /// inserted under SVG or MathML ones would screen a different tree than the browser builds.
    /// Sanitize such a fragment as part of the markup that establishes the foreign context - an
    /// <c>&lt;svg&gt;</c> element and its content together - with
    /// <see cref="Sanitize(string, string, IMarkupFormatter)"/> instead.
    /// </para>
    /// <para>
    /// Elements whose content model is raw text - <c>style</c>, <c>script</c>, <c>xmp</c>,
    /// <c>iframe</c>, <c>noembed</c> and <c>noframes</c> - are rejected. In those contexts the
    /// parser produces one text node instead of a tree, so there are no tags or attributes left for
    /// the sanitizer to act on and none of the markup is escaped on the way out; the input would be
    /// returned verbatim, giving the appearance of sanitization while performing none.
    /// </para>
    /// <para>
    /// A fragment is parsed into a document of its own, whose only element is the stand-in for the
    /// context, and the fragment hangs off that stand-in detached from the document's tree. That
    /// document is what <see cref="PostProcessDom"/> handlers are given, so a handler written for
    /// <see cref="Sanitize(string, string, IMarkupFormatter)"/> finds neither a body - the property
    /// is null - nor the fragment's nodes below it. Handlers that need the nodes should use
    /// <see cref="PostProcessNode"/>, which is raised for each of them as usual.
    /// </para>
    /// </remarks>
    /// <param name="html">The HTML fragment to sanitize.</param>
    /// <param name="context">The element the fragment will be inserted into.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
    /// <returns>The sanitized HTML fragment.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="html"/> or <paramref name="context"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="context"/> is not in the HTML namespace, or is an element whose content is raw text.
    /// </exception>
    public string SanitizeFragment(string html, IElement context, string baseUrl = "", IMarkupFormatter? outputFormatter = null) =>
        SanitizeFragment(html, context, baseUrl, outputFormatter, parser: null);

    /// <summary>
    /// Sanitizes a fragment in the context of the given element, optionally with a parser the caller
    /// has already taken from <see cref="HtmlParserFactory"/>.
    /// </summary>
    /// <remarks>
    /// The overload taking a tag name has to build the context element before it can parse the
    /// fragment, and building it needs a parser too. Passing that parser on keeps the factory called
    /// once per sanitize either way, which matters for a factory that returns a new parser per call
    /// or that counts its calls.
    /// </remarks>
    private string SanitizeFragment(string html, IElement context, string baseUrl,
        IMarkupFormatter? outputFormatter, HtmlParser? parser)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (context == null) throw new ArgumentNullException(nameof(context));

        // Only the local name of the context survives into the parse: ParseFragment rebuilds the
        // context in the HTML namespace, so an SVG or MathML element does not put the parser into
        // foreign content the way the same element does inside a document. Parsing under HTML rules
        // markup that will be inserted under foreign ones screens a different tree than the browser
        // builds, which is the guarantee this method exists to give, so those contexts are rejected
        // rather than silently mis-parsed.
        //
        // Rejecting them is also what makes the raw text check below sound. That check reads the
        // flags of the element handed in, but the parse runs in the HTML element of the same name,
        // and the two disagree outside the HTML namespace: an SVG <script> carries SvgMember alone,
        // no LiteralText, while the parse it produces is an HTML <script> - raw text, emitted
        // verbatim. Checking the flags here would pass and the input would come back unsanitized.
        if (context.NamespaceUri != NamespaceNames.HtmlUri)
            throw new ArgumentException(
                $"'{context.LocalName}' is not in the HTML namespace. The fragment parser takes only the " +
                "local name of the context and parses in the HTML namespace, so a fragment meant for " +
                "foreign content would be parsed by rules other than the ones it will be inserted under.",
                nameof(context));

        if (context.Flags.HasFlag(NodeFlags.LiteralText))
            throw new ArgumentException(
                $"'{context.LocalName}' holds raw text, so a fragment parsed in it cannot be sanitized. " +
                "Sanitize the fragment in the context it will be rendered as markup in instead.",
                nameof(context));

        parser ??= HtmlParserFactory();

        var nodes = parser.ParseFragment(html, context);

        if (nodes.Length == 0) return string.Empty;

        // ParseFragment builds the nodes under a stand-in for the context element inside a document
        // of its own, and that stand-in is the parent to sanitize within: it holds exactly the fragment
        // and nothing else, while still standing in for the context so selectors and the CSS object
        // model see the same shape the fragment will have once inserted.
        if (nodes[0].Parent is not INode parent || parent is not IParentNode parentNode) return string.Empty;

        // The parent stands in for the document here, rather than the document it belongs to, because
        // the fragment hangs off it without being attached to that document's tree: a style element
        // inside the fragment is registered in neither the document's stylesheet list nor its
        // descendants, so sanitizing from the document would search past the fragment entirely and
        // leave its CSS untouched. Post processing still reaches the document through the parent's
        // owner, which is set even while the subtree is detached.
        //
        // That document is one ParseFragment created for this call and holds resources of its own,
        // as the one Sanitize parses does, so it is disposed here as well - after the output has
        // been rendered from the subtree, which the using scope ensures.
        using var fragmentOwner = parent.Owner;

        DoSanitize(parent, parentNode, baseUrl);

        return parent.ChildNodes.ToHtml(outputFormatter ?? OutputFormatter);
    }

    /// <summary>
    /// Sanitizes the specified HTML document. Even if only a fragment is given, a whole document will be returned.
    /// </summary>
    /// <param name="html">The HTML document to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
    /// <returns>The sanitized HTML document.</returns>
    public string SanitizeDocument(string html, string baseUrl = "", IMarkupFormatter? outputFormatter = null)
    {
        var parser = HtmlParserFactory();
        using var dom = parser.ParseDocument(html);

        DoSanitize(dom, dom, baseUrl);

        var output = dom.ToHtml(outputFormatter ?? OutputFormatter);

        return output;
    }

    /// <summary>
    /// Sanitizes the specified HTML document. Even if only a fragment is given, a whole document will be returned.
    /// </summary>
    /// <param name="html">The HTML document to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
    /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
    /// <returns>The sanitized HTML document.</returns>
    public string SanitizeDocument(Stream html, string baseUrl = "", IMarkupFormatter? outputFormatter = null)
    {
        var parser = HtmlParserFactory();
        using var dom = parser.ParseDocument(html);

        DoSanitize(dom, dom, baseUrl);

        var output = dom.ToHtml(outputFormatter ?? OutputFormatter);

        return output;
    }

    /// <summary>
    /// Removes all comment nodes from a list of nodes.
    /// </summary>
    /// <param name="context">The node within which to remove comments.</param>
    /// <returns><c>true</c> if any comments were removed; otherwise, <c>false</c>.</returns>
    private void RemoveComments(INode context)
    {
        foreach (var comment in GetAllNodes(context).OfType<IComment>().ToList())
        {
            EncodeComment(comment);

            var e = new RemovingCommentEventArgs(comment);
            OnRemovingComment(e);

            if (!e.Cancel)
                comment.Remove();
        }
    }

    private static void DefaultEncodeComment(IComment comment)
    {
        var escapedText = comment.TextContent.Replace("<", "&lt;").Replace(">", "&gt;");
        if (escapedText != comment.TextContent)
            comment.TextContent = escapedText;
    }

    private static void DefaultEncodeLiteralTextElementContent(IElement tag)
    {
        var escapedHtml = tag.InnerHtml.Replace("<", "&lt;").Replace(">", "&gt;");
        if (escapedHtml != tag.InnerHtml)
            tag.InnerHtml = escapedHtml;
        if (tag.InnerHtml != escapedHtml) // setting InnerHtml does not work for noscript
            tag.SetInnerText(escapedHtml);
    }

    /// <summary>
    /// Fills <paramref name="buffer"/> with the attributes of <paramref name="tag"/> that match
    /// <paramref name="predicate"/>, or with all of them when it is <c>null</c>.
    /// </summary>
    /// <remarks>
    /// Attributes have to be copied out before a pass over them can add, remove or rewrite any,
    /// and the passes in <see cref="DoSanitize"/> run over every element of the document. Filling a
    /// caller-owned buffer by index keeps that off the allocator: a LINQ filter would allocate a
    /// closure, an iterator and a list per pass per element, and <see cref="INamedNodeMap"/> hands
    /// out a heap-allocated enumerator on top of that. The predicate is passed the sanitizer rather
    /// than capturing it so it can stay <c>static</c>, which is what keeps the closure away.
    /// </remarks>
    private void Snapshot(List<IAttr> buffer, IElement tag, Func<HtmlSanitizer, IAttr, bool>? predicate)
    {
        buffer.Clear();

        var attributes = tag.Attributes;

        for (var i = 0; i < attributes.Length; i++)
        {
            // Indexed access is annotated as nullable even though a well-formed map returns an
            // attribute for every index below Length; enumerating never yields null, so skipping
            // here keeps this identical to the enumeration it replaces.
            if (attributes[i] is not { } attribute)
                continue;

            if (predicate == null || predicate(this, attribute))
                buffer.Add(attribute);
        }
    }

    private void DoSanitize(INode dom, IParentNode context, string baseUrl = "", int srcdocDepth = 0)
    {
        // remove disallowed tags
        foreach (var tag in context.QuerySelectorAll("*").Where(t => !IsAllowedTag(t)).ToList())
        {
            RemoveTag(tag, RemoveReason.NotAllowedTag);
        }

        // always encode text in raw data content, except in style elements: their content is
        // sanitized as CSS by SanitizeStyleSheets below, which owns every style element.
        //
        // Matched by local name rather than by type on purpose. A <style> keeps the namespace it
        // was parsed in, and AngleSharp gives each namespace a different class: HtmlStyleElement
        // in HTML, SvgStyleElement in SVG, and in MathML a plain MathElement with no style
        // interface at all. So "is IHtmlStyleElement" would let the SVG and MathML ones fall
        // through to the encoder and out of the CSS sanitizer, and even ILinkStyle - shared by
        // the HTML and SVG classes - would still miss MathML. The local name catches all three.
        foreach (var tag in context.QuerySelectorAll("*")
            .Where(t => t.LocalName != StyleTagName
                && t.Flags.HasFlag(NodeFlags.LiteralText)
                && !string.IsNullOrWhiteSpace(t.InnerHtml)))
        {
            EncodeLiteralTextElementContent(tag);
        }

        SanitizeStyleSheets(dom, baseUrl);

        // Reused across every element and every pass below rather than allocated per pass. Each
        // pass has to take its own snapshot - the loop bodies add, remove and rewrite attributes,
        // which would otherwise mutate the collection being walked - but the snapshots do not
        // overlap in time, so one buffer serves them all.
        var attributeBuffer = new List<IAttr>();

        // cleanup attributes
        foreach (var tag in context.QuerySelectorAll("*").ToList())
        {
            if (tag is IHtmlTemplateElement templateElement && templateElement.Content is IDocumentFragment fragment)
            {
                DoSanitize(fragment, fragment, baseUrl, srcdocDepth);
            }

            // remove disallowed attributes
            Snapshot(attributeBuffer, tag, static (s, a) => !s.IsAllowedAttribute(a));
            foreach (var attribute in attributeBuffer)
            {
                RemoveAttribute(tag, attribute, RemoveReason.NotAllowedAttribute);
            }

            // sanitize the content of a surviving srcdoc attribute
            SanitizeSrcdoc(tag, baseUrl, srcdocDepth);

            // sanitize URLs in URL-marked attributes
            Snapshot(attributeBuffer, tag, static (s, a) => s.IsUriAttribute(a) && !s.IsUriListAttribute(a));
            foreach (var attribute in attributeBuffer)
            {
                var url = SanitizeUrl(tag, attribute.Value, baseUrl);

                if (url == null)
                    RemoveAttribute(tag, attribute, RemoveReason.NotAllowedUrlValue);
                else
                    tag.SetAttribute(attribute.Name, url);
            }

            // sanitize every entry of attributes holding a list of URLs
            Snapshot(attributeBuffer, tag, static (s, a) => s.IsUriListAttribute(a));
            foreach (var attribute in attributeBuffer)
            {
                SanitizeUriList(tag, attribute, baseUrl);
            }

            // sanitize the style attribute
            var oldStyleEmpty = string.IsNullOrEmpty(tag.GetAttribute(StyleAttributeName));
            SanitizeStyle(tag, baseUrl);

            // sanitize the value of the attributes
            Snapshot(attributeBuffer, tag, null);
            foreach (var attribute in attributeBuffer)
            {
                // The '& Javascript include' is a possible method to execute Javascript and can lead to XSS.
                // (see https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#.26_JavaScript_includes)
                if (attribute.Value.Contains("&{"))
                {
                    RemoveAttribute(tag, attribute, RemoveReason.NotAllowedValue);
                }
                else
                {
                    if (AllowedClasses.Any() && attribute.Name == "class")
                    {
                        var removedClasses = tag.ClassList.Except(AllowedClasses).ToArray();

                        foreach (var removedClass in removedClasses)
                            RemoveCssClass(tag, removedClass, RemoveReason.NotAllowedCssClass);

                        if (tag.ClassList.Length == 0)
                            RemoveAttribute(tag, attribute, RemoveReason.ClassAttributeEmpty);
                    }
                    else if (!oldStyleEmpty && attribute.Name == StyleAttributeName && string.IsNullOrEmpty(attribute.Value))
                    {
                        RemoveAttribute(tag, attribute, RemoveReason.StyleAttributeEmpty);
                    }
                }
            }
        }

        if (context is INode node)
        {
            RemoveComments(node);
        }

        var doc = dom as IHtmlDocument ?? dom.Owner as IHtmlDocument;

        if (doc != null)
        {
            DoPostProcess(doc, context as INode);
        }
    }

    /// <summary>
    /// Sanitizes an attribute whose value is a list of URLs, screening each entry on its own.
    /// </summary>
    /// <remarks>
    /// Screening the raw value as a single URL would only ever examine the first entry, letting
    /// <c>srcset="ok.jpg 1x, javascript:alert(1) 2x"</c> through intact. Entries that fail are
    /// dropped individually and the surviving ones are kept, so hostile candidates are removed
    /// without discarding the usable ones; the attribute goes only when nothing is left.
    /// <para>
    /// <c>srcset</c> is parsed with AngleSharp's <see cref="SourceSet"/>, which implements the
    /// HTML candidate-string grammar - a comma separates candidates, but a comma may also sit
    /// inside a URL, so splitting the text naively would corrupt valid values. The other list
    /// attributes are whitespace-separated and need no such grammar.
    /// </para>
    /// </remarks>
    private void SanitizeUriList(IElement tag, IAttr attribute, string baseUrl)
    {
        var value = attribute.Value;

        if (string.IsNullOrWhiteSpace(value))
        {
            RemoveAttribute(tag, attribute, RemoveReason.NotAllowedUrlValue);
            return;
        }

        var sanitized = attribute.Name.Equals(SrcsetAttributeName, StringComparison.OrdinalIgnoreCase)
            ? SanitizeSrcset(tag, value, baseUrl)
            : SanitizeUrlList(tag, value, baseUrl);

        if (sanitized == null)
            RemoveAttribute(tag, attribute, RemoveReason.NotAllowedUrlValue);
        else
            tag.SetAttribute(attribute.Name, sanitized);
    }

    /// <summary>
    /// Screens each candidate of a <c>srcset</c> value, preserving the descriptor that belongs to
    /// each surviving URL. Returns null when no candidate survives.
    /// </summary>
    private string? SanitizeSrcset(IElement tag, string value, string baseUrl)
    {
        var kept = new List<string>();

        foreach (var candidate in SourceSet.Parse(value))
        {
            var candidateUrl = candidate.Url;

            if (candidateUrl == null || candidateUrl.Length == 0) continue;

            var url = SanitizeUrl(tag, candidateUrl, baseUrl);

            if (url == null) continue;

            kept.Add(string.IsNullOrEmpty(candidate.Descriptor)
                ? url
                : $"{url} {candidate.Descriptor}");
        }

        return kept.Count > 0 ? string.Join(", ", kept) : null;
    }

    /// <summary>
    /// Screens each entry of a whitespace-separated URL list such as <c>ping</c> or
    /// <c>archive</c>. Returns null when no entry survives.
    /// </summary>
    private string? SanitizeUrlList(IElement tag, string value, string baseUrl)
    {
        var kept = new List<string>();

        foreach (var entry in value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            var url = SanitizeUrl(tag, entry, baseUrl);

            if (url != null) kept.Add(url);
        }

        return kept.Count > 0 ? string.Join(" ", kept) : null;
    }

    /// <summary>
    /// Sanitizes the content of a <c>srcdoc</c> attribute, which holds a nested HTML document
    /// rather than a URL or plain text.
    /// </summary>
    /// <remarks>
    /// A browser parses <c>srcdoc</c> into its own browsing context and runs whatever it finds,
    /// so an unsanitized value is an unfiltered script channel. It cannot be secured the way
    /// other attributes are: marking it as a URI attribute applies URL screening, which is the
    /// wrong check for markup, and leaving it to <see cref="AllowedAttributes"/> alone gives
    /// callers no safe way to permit the attribute at all. Instead the value is sanitized as
    /// HTML with this same sanitizer, so the nested document is held to exactly the policy the
    /// outer one is.
    /// </remarks>
    private void SanitizeSrcdoc(IElement tag, string baseUrl, int srcdocDepth)
    {
        var attribute = tag.Attributes.FirstOrDefault(a =>
            a.Name.Equals(SrcdocAttributeName, StringComparison.OrdinalIgnoreCase));

        if (attribute == null || string.IsNullOrEmpty(attribute.Value))
            return;

        // Nested srcdoc documents each cost a full parse. Rather than recurse without bound,
        // drop the attribute once the limit is reached: the nested content is unexamined at that
        // point, so keeping it would be keeping something unsanitized.
        if (srcdocDepth >= MaxSrcdocDepth)
        {
            RemoveAttribute(tag, attribute, RemoveReason.NotAllowedValue);
            return;
        }

        var parser = HtmlParserFactory();
        using var nested = parser.ParseDocument("<!doctype html><html><body>" + attribute.Value);

        if (nested.Body == null)
        {
            RemoveAttribute(tag, attribute, RemoveReason.NotAllowedValue);
            return;
        }

        DoSanitize(nested, nested.Body, baseUrl, srcdocDepth + 1);

        tag.SetAttribute(attribute.Name, nested.Body.ChildNodes.ToHtml(OutputFormatter));
    }

    private void SanitizeStyleSheets(INode node, string baseUrl)
    {
        var handled = new HashSet<IElement>();

        foreach (var styleSheet in node.GetStyleSheets().OfType<ICssStyleSheet>())
        {
            SanitizeStyleSheet(styleSheet, styleSheet.OwnerNode, baseUrl);
            handled.Add(styleSheet.OwnerNode);
        }

        // The CSS object model only exposes a stylesheet for a style element whose type attribute
        // it recognizes as CSS. A <style type=""> is applied as CSS by browsers - the HTML standard
        // defaults an absent *or empty* type to text/css - but yields no stylesheet here, so its
        // content would reach the output untouched: it is neither sanitized above nor encoded as
        // literal text in DoSanitize. Recover a stylesheet for whatever the loop above did not
        // cover by re-parsing the element's content as a fresh, type-less <style> tag through the
        // configured HtmlParserFactory - the CSS object model always recognizes that - rather than
        // reproducing the MIME matching of each browser, which is what left the gap. Using
        // HtmlParserFactory here, the same factory the rest of the document was parsed with, keeps
        // this path's CSS parsing options in sync with the primary one instead of needing a second,
        // independently configured parser that could drift out of step with it.
        if (node is not IParentNode parent)
            return;

        foreach (var styleTag in parent.QuerySelectorAll(StyleTagName).Where(t => !handled.Contains(t)).ToList())
        {
            var reparsed = HtmlParserFactory().ParseDocument($"<style>{styleTag.TextContent}</style>");
            var styleSheet = reparsed.GetStyleSheets().OfType<ICssStyleSheet>().FirstOrDefault();

            if (styleSheet != null)
                SanitizeStyleSheet(styleSheet, styleTag, baseUrl);
            else
                // A type-less <style> tag should always yield a stylesheet; if it somehow doesn't,
                // fail closed rather than leaving the original, unsanitized content in place.
                styleTag.InnerHtml = string.Empty;
        }
    }

    private void SanitizeStyleSheet(ICssStyleSheet styleSheet, IElement styleTag, string baseUrl)
    {
        var i = 0;

        while (i < styleSheet.Rules.Length)
        {
            var rule = styleSheet.Rules[i];
            if (!SanitizeStyleRule(rule, styleTag, baseUrl) && RemoveAtRule(styleTag, rule))
                styleSheet.RemoveAt(i);
            else i++;
        }

        styleTag.InnerHtml = styleSheet.ToCss(StyleFormatter).Replace("<", "\\3c ");
    }

    private bool SanitizeStyleRule(ICssRule rule, IElement styleTag, string baseUrl)
    {
        if (!AllowedAtRules.Contains(rule.Type)) return false;

        if (FilterCssRule != null)
        {
            var e = new FilterCssRuleEventArgs(styleTag, rule, baseUrl);
            if (!OnFilteringCssRule(e))
                return false;
        }

        if (rule is ICssStyleRule styleRule)
        {
            SanitizeStyleDeclaration(styleTag, styleRule.Style, baseUrl);
        }
        else
        {
            if (rule is ICssGroupingRule groupingRule)
            {
                var i = 0;

                while (i < groupingRule.Rules.Length)
                {
                    var childRule = groupingRule.Rules[i];
                    if (!SanitizeStyleRule(childRule, styleTag, baseUrl) && RemoveAtRule(styleTag, childRule))
                        groupingRule.RemoveAt(i);
                    else i++;
                }
            }
            else if (rule is ICssPageRule pageRule)
            {
                SanitizeStyleDeclaration(styleTag, pageRule.Style, baseUrl);
            }
            else if (rule is ICssKeyframesRule keyFramesRule)
            {
                foreach (var childRule in keyFramesRule.Rules.OfType<ICssKeyframeRule>()
                    .Where(r => !SanitizeStyleRule(r, styleTag, baseUrl) && RemoveAtRule(styleTag, r))
                    .ToList())
                {
                    keyFramesRule.Remove(childRule.KeyText);
                }
            }
            else if (rule is ICssKeyframeRule keyFrameRule)
            {
                SanitizeStyleDeclaration(styleTag, keyFrameRule.Style, baseUrl);
            }
            else if (rule is ICssFontFaceRule fontFaceRule)
            {
                return SanitizeFontFaceRule(styleTag, fontFaceRule, baseUrl);
            }
            else if (rule is ICssImportRule importRule)
            {
                // The browser fetches the imported style sheet, so its URL has to clear the same
                // scheme check as any other. The rule is not rewritten - that would mean rebuilding
                // its text and re-escaping the URL - so one that does not pass is dropped instead.
                return SanitizeUrl(styleTag, importRule.Href, baseUrl) != null;
            }
        }

        return true;
    }

    /// <summary>
    /// Sanitizes the declarations of an <c>@font-face</c> rule.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An <c>@font-face</c> rule carries declarations like a style rule does, but the CSS object
    /// model exposes them as <see cref="ICssProperties"/> rather than an
    /// <see cref="ICssStyleDeclaration"/>, so <see cref="SanitizeStyleDeclaration"/> cannot be
    /// reused. Checking them here is what keeps the <c>src</c> descriptor - a URL the browser
    /// really does request - subject to <see cref="AllowedSchemes"/> and to base URL resolution.
    /// </para>
    /// <para>
    /// The object model offers no way to drop a single declaration from the rule, and a font whose
    /// source has been taken away is of no use, so anything unacceptable removes the whole rule.
    /// </para>
    /// </remarks>
    /// <param name="styleTag">The style element the rule belongs to.</param>
    /// <param name="fontFaceRule">The rule to sanitize.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against.</param>
    /// <returns><c>true</c> if the rule can be kept; otherwise, <c>false</c>.</returns>
    private bool SanitizeFontFaceRule(IElement styleTag, ICssFontFaceRule fontFaceRule, string baseUrl)
    {
        // Materialized because the declarations are updated while going through them.
        foreach (var property in ((IEnumerable<ICssProperty>)fontFaceRule).ToList())
        {
            if (!IsAllowedCssProperty(DecodeCss(property.Name)))
                return false;

            var value = DecodeCss(property.Value);
            var sanitized = SanitizeCssValue(styleTag, value, baseUrl, out _);

            if (sanitized == null)
                return false;

            if (sanitized != value)
                property.Value = sanitized;
        }

        return true;
    }

    /// <summary>
    /// Performs post processing on all nodes in the document.
    /// </summary>
    /// <param name="dom">The HTML document.</param>
    /// <param name="context">The node within which to post process all nodes.</param>
    private void DoPostProcess(IHtmlDocument dom, INode? context)
    {
        if (PostProcessNode != null)
        {
            dom.Normalize();

            if (context != null)
            {
                var nodes = GetAllNodes(context).ToList();
                foreach (var node in nodes)
                {
                    var e = new PostProcessNodeEventArgs(dom, node);
                    OnPostProcessNode(e);
                    if (e.ReplacementNodes.Count != 0)
                    {
                        ((IChildNode)node).Replace([.. e.ReplacementNodes]);
                    }
                }
            }
        }

        if (PostProcessDom != null)
        {
            var e = new PostProcessDomEventArgs(dom);
            OnPostProcessDom(e);
        }
    }

    /// <summary>
    /// Determines whether the specified attribute can contain a URI.
    /// </summary>
    /// <param name="attribute">The attribute.</param>
    /// <returns><c>true</c> if the attribute can contain a URI; otherwise, <c>false</c>.</returns>
    private bool IsUriAttribute(IAttr attribute)
    {
        return UriAttributes.Contains(attribute.Name);
    }

    private bool IsUriListAttribute(IAttr attribute)
    {
        return UriListAttributes.Contains(attribute.Name);
    }

    /// <summary>
    /// Determines whether the specified tag is allowed.
    /// </summary>
    /// <param name="tag">The tag.</param>
    /// <returns><c>true</c> if the tag is allowed; otherwise, <c>false</c>.</returns>
    private bool IsAllowedTag(IElement tag)
    {
        return AllowedTags.Contains(tag.NodeName);
    }

    /// <summary>
    /// Determines whether the specified attribute is allowed.
    /// </summary>
    /// <param name="attribute">The attribute.</param>
    /// <returns><c>true</c> if the attribute is allowed; otherwise, <c>false</c>.</returns>
    private bool IsAllowedAttribute(IAttr attribute)
    {
        return AllowedAttributes.Contains(attribute.Name)
            // test html5 data- attributes
            || (AllowDataAttributes && attribute.Name != null && attribute.Name.StartsWith("data-", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Sanitizes the style.
    /// </summary>
    /// <param name="element">The element.</param>
    /// <param name="baseUrl">The base URL.</param>
    protected void SanitizeStyle(IElement element, string baseUrl)
    {
        // filter out invalid CSS declarations
        // see https://github.com/AngleSharp/AngleSharp/issues/101
        var attribute = element.GetAttribute(StyleAttributeName);
        if (attribute == null)
            return;

        if (element.GetStyle() == null)
        {
            element.RemoveAttribute(StyleAttributeName);
            return;
        }

        element.SetAttribute(StyleAttributeName, element.GetStyle().ToCss(StyleFormatter));

        var styles = element.GetStyle();
        if (styles == null || styles.Length == 0)
            return;

        SanitizeStyleDeclaration(element, styles, baseUrl);
    }

    /// <summary>
    /// Verify if the given CSS property name is allowed. By default this will
    /// check if the property is in the <see cref="AllowedCssProperties"/> set,
    /// or if the property is a custom property and <see cref="AllowCssCustomProperties"/> is true.
    /// </summary>
    /// <param name="propertyName">The name of the CSS property.</param>
    /// <returns>True if the property is allowed or not.</returns>
    protected virtual bool IsAllowedCssProperty(string propertyName)
    {
        return AllowedCssProperties.Contains(propertyName)
            || AllowCssCustomProperties && propertyName != null && propertyName.StartsWith("--");
    }

    private void SanitizeStyleDeclaration(IElement element, ICssStyleDeclaration styles, string baseUrl)
    {
        var pending = GetPendingShorthands(styles);
        var covered = pending.Count == 0 ? null
            : new HashSet<string>(pending.SelectMany(p => p.Longhands), StringComparer.OrdinalIgnoreCase);

        var removeStyles = new List<Tuple<ICssProperty, RemoveReason>>();
        var setStyles = new Dictionary<string, string>();

        // Checks one declaration's value - whether it belongs to an ordinary property or is a
        // shorthand recovered from a pending-substitution value below - against the same rules:
        // is the property allowed, is the value free of disallowed constructs, and is every URL
        // in it acceptable. Reports what the caller should do, rather than mutating the removal/
        // set collections itself: keeping the mutation visible at the call site (instead of hidden
        // behind a closure) is also what it takes for static analysis to see that those collections
        // can end up non-empty below.
        (ICssProperty? RemoveProperty, RemoveReason RemoveReason, string? SetKey, string? SetValue) Evaluate(ICssProperty property, string rawName, string rawValue)
        {
            var key = DecodeCss(rawName);
            var val = DecodeCss(rawValue);

            if (!IsAllowedCssProperty(key))
                return (property, RemoveReason.NotAllowedStyle, null, null);

            var sanitized = SanitizeCssValue(element, val, baseUrl, out var reason);

            if (sanitized == null)
                return (property, reason, null, null);

            if (sanitized != val)
            {
                return key != rawName
                    ? (property, RemoveReason.NotAllowedUrlValue, key, sanitized)
                    : (null, default, key, sanitized);
            }

            return (null, default, null, null);
        }

        foreach (var style in styles.Where(style => covered == null || !covered.Contains(style.Name)))
        {
            // The longhands of a pending-substitution shorthand carry no value of their own.
            // The shorthand that produced them is evaluated below instead.
            var (removeProperty, removeReason, setKey, setValue) = Evaluate(style, style.Name, style.Value);

            if (removeProperty != null)
                removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(removeProperty, removeReason));

            if (setKey != null)
                setStyles[setKey] = setValue!;
        }

        // Values recovered from pending-substitution shorthands go through exactly the same checks.
        foreach (var (name, value, _) in pending)
        {
            var (removeProperty, removeReason, setKey, setValue) = Evaluate(new ShorthandProperty(name, value), name, value);

            if (removeProperty != null)
                removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(removeProperty, removeReason));

            if (setKey != null)
                setStyles[setKey] = setValue!;
        }

        if (removeStyles.Count == 0 && setStyles.Count == 0)
            return;

        var removedNames = new HashSet<string>();

        foreach (var style in removeStyles)
        {
            var e = new RemovingStyleEventArgs(element, style.Item1, style.Item2);
            OnRemovingStyle(e);

            if (!e.Cancel)
                removedNames.Add(style.Item1.Name);
        }

        // Rebuild the declaration list once instead of mutating it property by property:
        // AngleSharp.Css re-serializes the whole style attribute on every SetProperty/RemoveProperty call,
        // which is quadratic in the number of declarations.
        var cssText = new StringBuilder();
        var written = pending.Count == 0 ? null : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var style in styles)
        {
            if (covered != null && covered.Contains(style.Name))
            {
                // Write the shorthand once, where its first longhand sits, so declaration order is
                // preserved. The longhands must not be written themselves: they serialize as
                // "background-image: " and the whole declaration would be lost on reparse.
                var (Name, Value, _) = pending.First(p => p.Longhands.Contains(style.Name));

                if (!written!.Add(Name))
                    continue;

                if (removedNames.Contains(Name))
                    continue;

                var value = setStyles.TryGetValue(DecodeCss(Name), out var newValue)
                    ? newValue
                    : Value;

                cssText.Append(Name).Append(':').Append(value).Append(';');

                continue;
            }

            if (removedNames.Contains(style.Name))
                continue;

            if (setStyles.TryGetValue(DecodeCss(style.Name), out var updatedValue))
                cssText.Append(style.Name).Append(':').Append(updatedValue).Append(';');
            else
                cssText.Append(style.ToCss()).Append(';');
        }

        styles.CssText = cssText.ToString();
    }

    /// <summary>
    /// Applies the value level checks to a single declaration value.
    /// </summary>
    /// <param name="element">The element the declaration belongs to.</param>
    /// <param name="value">The decoded declaration value.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against.</param>
    /// <param name="reason">The reason the declaration has to be removed, if it has to be.</param>
    /// <returns>The value to keep, with any URLs rewritten, or <c>null</c> if the declaration must be removed.</returns>
    private string? SanitizeCssValue(IElement element, string value, string baseUrl, out RemoveReason reason)
    {
        if (CssExpression.IsMatch(value) || DisallowCssPropertyValue.IsMatch(value))
        {
            reason = RemoveReason.NotAllowedValue;
            return null;
        }

        reason = RemoveReason.NotAllowedUrlValue;

        // Matching runs against the original value so that the spacing between tokens is preserved
        // when the value is rebuilt below. Whitespace inside the URL itself is removed before
        // validation so constructs like url(java script:alert(1)) can't smuggle a disallowed scheme
        // past the check; the value written back is what SanitizeUrl returned, so what is validated
        // is what is emitted.
        var urls = CssUrl.Matches(value).Cast<Match>()
            .Select(m => (Match: m, Url: WhitespaceRegex.Replace(m.Groups[2].Value, string.Empty)))
            // An empty url() has nothing to resolve or to validate, leave it alone.
            .Where(u => u.Url.Length > 0)
            .Select(u => (u.Match, Url: SanitizeUrl(element, u.Url, baseUrl)))
            .ToList();

        if (urls.Count == 0)
            return value;

        if (urls.Any(u => u.Url == null))
            return null;

        var sb = new StringBuilder();
        var ix = 0;

        foreach (var url in urls)
        {
            sb.Append(value, ix, url.Match.Index - ix);
            sb.Append("url(");
            sb.Append(url.Match.Groups[1].Value);
            sb.Append(url.Url);
            sb.Append(url.Match.Groups[3].Value);
            sb.Append(')');
            ix = url.Match.Index + url.Match.Length;
        }

        sb.Append(value, ix, value.Length - ix);

        return sb.ToString();
    }

    /// <summary>
    /// Finds the declarations that the CSS object model refuses to expose through its longhands.
    /// </summary>
    /// <remarks>
    /// A shorthand whose value contains <c>var()</c> becomes a pending-substitution value: per the
    /// CSS custom properties spec its longhands serialize as the empty string, so the per-property
    /// checks would see nothing at all and the declaration would pass through unexamined. Recover
    /// the shorthand that produced those longhands, together with the text the author actually
    /// wrote, so it can be checked like any other value.
    /// </remarks>
    /// <param name="styles">The declaration block.</param>
    /// <returns>The recovered shorthands, empty if the block has none.</returns>
    private static List<(string Name, string Value, HashSet<string> Longhands)> GetPendingShorthands(ICssStyleDeclaration styles)
    {
        var pending = new List<(string, string, HashSet<string>)>();
        HashSet<string>? opaque = null;

        foreach (var style in styles.Where(s => string.IsNullOrEmpty(s.Value)))
        {
            (opaque ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase)).Add(style.Name);
        }

        // An empty longhand is not proof of a pending value on its own: "font: 12px/1.5 Arial"
        // leaves the sub-properties it omits empty as well. Those are weeded out below by the
        // requirement that a shorthand account for all of its longhands.
        if (opaque == null)
            return pending;

        // A longhand can belong to more than one shorthand (border-top-color is reachable from
        // border, border-top and border-color). Take the widest shorthand the opaque longhands
        // fully cover first, then drop what it accounts for, so a narrower overlapping shorthand
        // cannot claim them as well and widen the declaration on the way out.
        var candidates = opaque
            .SelectMany(GetShorthands)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(name => (Name: name, Longhands: GetLonghands(name)))
            .OrderByDescending(c => c.Longhands.Count)
            .ToList();

        foreach (var (name, longhands) in candidates)
        {
            if (longhands.Count == 0 || !longhands.All(opaque.Contains))
                continue;

            var value = styles.GetPropertyValue(name);

            // Only one of the candidates is the shorthand that was actually declared; the others
            // answer with the empty string.
            if (string.IsNullOrEmpty(value))
                continue;

            pending.Add((name, value, longhands));
            opaque.ExceptWith(longhands);
        }

        return pending;
    }

    /// <summary>
    /// Gets the shorthand properties a property is part of.
    /// </summary>
    private static string[] GetShorthands(string property) =>
        shorthandsOf.GetOrAdd(property, static p => declarationFactory.Create(p)?.Shorthands ?? []);

    /// <summary>
    /// Expands a property into the set of longhand properties it ultimately controls.
    /// </summary>
    private static HashSet<string> GetLonghands(string property) =>
        longhandsOf.GetOrAdd(property, static p =>
        {
            var longhands = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Expand(p, longhands, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            return longhands;
        });

    private static void Expand(string property, HashSet<string> longhands, HashSet<string> visited)
    {
        if (!visited.Add(property))
            return;

        var children = declarationFactory.Create(property)?.Longhands;

        if (children == null || children.Length == 0)
        {
            longhands.Add(property);
            return;
        }

        foreach (var child in children)
            Expand(child, longhands, visited);
    }

    /// <summary>
    /// Stands in for a shorthand declaration that the CSS object model only exposes as a
    /// pending-substitution value, so that <see cref="RemovingStyle"/> reports the property the
    /// author wrote rather than one of the empty longhands it expands to.
    /// </summary>
    private sealed class ShorthandProperty(string name, string value) : ICssProperty
    {
        public string Name { get; } = name;
        public string Value { get; set; } = value;
        public bool IsImportant { get; set; }
        public ICssValue RawValue => null!;
        public bool IsInherited => false;
        public bool IsInitial => false;
        public bool IsAnimatable => false;
        public bool CanBeInherited => false;
        public bool IsShorthand => true;
        public ICssProperty Compute(ICssComputeContext context) => this;
        public void ToCss(TextWriter writer, IStyleFormatter formatter) =>
            writer.Write(formatter.Declaration(Name, Value, IsImportant));
    }

    /// <summary>
    /// Decodes CSS Unicode escapes and removes comments.
    /// </summary>
    /// <param name="css">The CSS string.</param>
    /// <returns>The decoded CSS string.</returns>
    protected static string DecodeCss(string css)
    {
        var r = CssUnicodeEscapes.Replace(css, m =>
        {
            if (m.Groups[1].Success)
                return ((char)int.Parse(m.Groups[1].Value, NumberStyles.HexNumber)).ToString();
            var t = m.Groups[2].Value;
            return t == "\\" ? @"\\" : t;
        });

        r = CssComments.Replace(r, m => "");

        return r;
    }

    private static readonly Regex SchemeRegex = new(@"^([^\/#]*?)(?:\:|&#0*58|&#x0*3a)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Tries to create a safe <see cref="Iri"/> object from a string.
    /// </summary>
    /// <param name="url">The URL.</param>
    /// <returns>The <see cref="Iri"/> object or null if no safe <see cref="Iri"/> can be created.</returns>
    protected Iri? GetSafeIri(string url)
    {
        url = url.TrimStart();

        var schemeMatch = SchemeRegex.Match(url);

        if (schemeMatch.Success)
        {
            var scheme = schemeMatch.Groups[1].Value;
            return AllowedSchemes.Contains(scheme, StringComparer.OrdinalIgnoreCase) ? new Iri(url, scheme) : null;
        }

        return new Iri(url);
    }

    /// <summary>
    /// Sanitizes a URL.
    /// </summary>
    /// <param name="element">The tag containing the URL being sanitized.</param>
    /// <param name="url">The URL.</param>
    /// <param name="baseUrl">The base URL relative URLs are resolved against (empty or null for no resolution).</param>
    /// <returns>The sanitized URL or <c>null</c> if no safe URL can be created.</returns>
    protected virtual string? SanitizeUrl(IElement element, string url, string baseUrl)
    {
        var iri = GetSafeIri(url);

        if (iri != null && !iri.IsAbsolute && !string.IsNullOrEmpty(baseUrl))
        {
            // resolve relative URI
            if (Uri.TryCreate(baseUrl, UriKind.Absolute, out Uri? baseUri))
            {
                try
                {
                    var resolvedUri = new Uri(baseUri, iri.Value);

                    if (!AllowedSchemes.Contains(resolvedUri.Scheme, StringComparer.OrdinalIgnoreCase))
                    {
                        iri = null;
                    }
                    else
                    {
                        var sanitizedUrl = resolvedUri.AbsoluteUri;
                        var ev = new FilterUrlEventArgs(element, url, sanitizedUrl);

                        OnFilteringUrl(ev);

                        return ev.SanitizedUrl;
                    }
                }
                catch (UriFormatException)
                {
                    iri = null;
                }
            }
            else iri = null;
        }

        var e = new FilterUrlEventArgs(element, url, iri?.Value);
        OnFilteringUrl(e);

        return e.SanitizedUrl;
    }

    /// <summary>
    /// Removes a tag from the document.
    /// </summary>
    /// <param name="tag">Tag to be removed.</param>
    /// <param name="reason">Reason for removal.</param>
    private void RemoveTag(IElement tag, RemoveReason reason)
    {
        var e = new RemovingTagEventArgs(tag, reason);
        OnRemovingTag(e);

        if (!e.Cancel)
        {
            if (KeepChildNodes && tag.HasChildNodes)
                tag.Replace([.. tag.ChildNodes]);
            else
                tag.Remove();
        }
    }

    /// <summary>
    /// Removes an attribute from the document.
    /// </summary>
    /// <param name="tag">Tag the attribute belongs to.</param>
    /// <param name="attribute">Attribute to be removed.</param>
    /// <param name="reason">Reason for removal.</param>
    private void RemoveAttribute(IElement tag, IAttr attribute, RemoveReason reason)
    {
        var e = new RemovingAttributeEventArgs(tag, attribute, reason);
        OnRemovingAttribute(e);

        if (!e.Cancel)
            tag.RemoveAttribute(attribute.Name);
    }

    /// <summary>
    /// Removes an at-rule from the document.
    /// </summary>
    /// <param name="tag">Tag the style belongs to.</param>
    /// <param name="rule">Rule to be removed.</param>
    /// <returns><c>true</c>, if the rule can be removed; <c>false</c>, otherwise.</returns>
    private bool RemoveAtRule(IElement tag, ICssRule rule)
    {
        var e = new RemovingAtRuleEventArgs(tag, rule);
        OnRemovingAtRule(e);

        return !e.Cancel;
    }

    /// <summary>
    /// Removes a CSS class from a class attribute.
    /// </summary>
    /// <param name="tag">Tag the style belongs to.</param>
    /// <param name="cssClass">Class to be removed.</param>
    /// <param name="reason">Reason for removal.</param>
    private void RemoveCssClass(IElement tag, string cssClass, RemoveReason reason)
    {
        var e = new RemovingCssClassEventArgs(tag, cssClass, reason);
        OnRemovingCssClass(e);

        if (!e.Cancel)
            tag.ClassList.Remove(cssClass);
    }
}
