using AngleSharp;
using AngleSharp.Css.Dom;
using AngleSharp.Css.Parser;
using AngleSharp.Dom;
using AngleSharp.Html.Dom;
using AngleSharp.Html.Parser;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Ganss.XSS
{
    /// <summary>
    /// Cleans HTML documents and fragments from constructs that can lead to <a href="https://en.wikipedia.org/wiki/Cross-site_scripting">XSS attacks</a>.
    /// </summary>
    /// <remarks>
    /// XSS attacks can occur at several levels within an HTML document or fragment:
    /// <list type="bullet">
    /// <item>HTML Tags (e.g. the &lt;script&gt; tag)</item>
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
        /// <summary>
        /// Initializes a new instance of the <see cref="HtmlSanitizer"/> class.
        /// </summary>
        /// <param name="allowedTags">The allowed tag names such as "a" and "div". When <c>null</c>, uses <see cref="DefaultAllowedTags"/></param>
        /// <param name="allowedSchemes">The allowed HTTP schemes such as "http" and "https". When <c>null</c>, uses <see cref="DefaultAllowedSchemes"/></param>
        /// <param name="allowedAttributes">The allowed HTML attributes such as "href" and "alt". When <c>null</c>, uses <see cref="DefaultAllowedAttributes"/></param>
        /// <param name="uriAttributes">The HTML attributes that can contain a URI such as "href". When <c>null</c>, uses <see cref="DefaultUriAttributes"/></param>
        /// <param name="allowedCssProperties">The allowed CSS properties such as "font" and "margin". When <c>null</c>, uses <see cref="DefaultAllowedCssProperties"/></param>
        public HtmlSanitizer(IEnumerable<string> allowedTags = null, IEnumerable<string> allowedSchemes = null,
            IEnumerable<string> allowedAttributes = null, IEnumerable<string> uriAttributes = null, IEnumerable<string> allowedCssProperties = null)
        {
            AllowedTags = new HashSet<string>(allowedTags ?? DefaultAllowedTags, StringComparer.OrdinalIgnoreCase);
            AllowedSchemes = new HashSet<string>(allowedSchemes ?? DefaultAllowedSchemes, StringComparer.OrdinalIgnoreCase);
            AllowedAttributes = new HashSet<string>(allowedAttributes ?? DefaultAllowedAttributes, StringComparer.OrdinalIgnoreCase);
            UriAttributes = new HashSet<string>(uriAttributes ?? DefaultUriAttributes, StringComparer.OrdinalIgnoreCase);
            AllowedCssProperties = new HashSet<string>(allowedCssProperties ?? DefaultAllowedCssProperties, StringComparer.OrdinalIgnoreCase);
            AllowedAtRules = new HashSet<CssRuleType>(DefaultAllowedAtRules);
            AllowedClasses = new HashSet<string>(DefaultAllowedClasses, StringComparer.OrdinalIgnoreCase);
        }

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
        public static Func<HtmlParser> DefaultHtmlParserFactory { get; set; } = CreateParser;

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
        /// Gets or sets the allowed CSS at-rules such as "@media" and "@font-face".
        /// </summary>
        /// <value>
        /// The allowed CSS at-rules.
        /// </value>
        public ISet<CssRuleType> AllowedAtRules { get; private set; }

        /// <summary>
        /// The default allowed CSS at-rules.
        /// </summary>
        public static ISet<CssRuleType> DefaultAllowedAtRules { get; } = new HashSet<CssRuleType>() { CssRuleType.Style, CssRuleType.Namespace };

        /// <summary>
        /// Gets or sets the allowed HTTP schemes such as "http" and "https".
        /// </summary>
        /// <value>
        /// The allowed HTTP schemes.
        /// </value>
        public ISet<string> AllowedSchemes { get; private set; }

        /// <summary>
        /// The default allowed URI schemes.
        /// </summary>
        public static ISet<string> DefaultAllowedSchemes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" };

        /// <summary>
        /// Gets or sets the allowed HTML tag names such as "a" and "div".
        /// </summary>
        /// <value>
        /// The allowed tag names.
        /// </value>
        public ISet<string> AllowedTags { get; private set; }

        /// <summary>
        /// The default allowed HTML tag names.
        /// </summary>
        public static ISet<string> DefaultAllowedTags { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            // https://developer.mozilla.org/en/docs/Web/Guide/HTML/HTML5/HTML5_element_list
            "a", "abbr", "acronym", "address", "area", "b",
            "big", "blockquote", "br", "button", "caption", "center", "cite",
            "code", "col", "colgroup", "dd", "del", "dfn", "dir", "div", "dl", "dt",
            "em", "fieldset", "font", "form", "h1", "h2", "h3", "h4", "h5", "h6",
            "hr", "i", "img", "input", "ins", "kbd", "label", "legend", "li", "map",
            "menu", "ol", "optgroup", "option", "p", "pre", "q", "s", "samp",
            "select", "small", "span", "strike", "strong", "sub", "sup", "table",
            "tbody", "td", "textarea", "tfoot", "th", "thead", "tr", "tt", "u",
            "ul", "var",
            // HTML5
            // Sections
            "section", "nav", "article", "aside", "header", "footer", "main",
            // Grouping content
            "figure", "figcaption",
            // Text-level semantics
            "data", "time", "mark", "ruby", "rt", "rp", "bdi", "wbr",
            // Forms
            "datalist", "keygen", "output", "progress", "meter",
            // Interactive elements
            "details", "summary", "menuitem",
            // document elements
            "html", "head", "body"
        };

        /// <summary>
        /// Gets or sets the allowed HTML attributes such as "href" and "alt".
        /// </summary>
        /// <value>
        /// The allowed HTML attributes.
        /// </value>
        public ISet<string> AllowedAttributes { get; private set; }

        /// <summary>
        /// Allow all HTML5 data attributes; the attributes prefixed with data-
        /// </summary>
        public bool AllowDataAttributes { get; set; }

        /// <summary>
        /// The default allowed HTML attributes.
        /// </summary>
        public static ISet<string> DefaultAllowedAttributes { get; }  = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            // https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes
            "abbr", "accept", "accept-charset", "accesskey",
            "action", "align", "alt", "axis", "bgcolor", "border", "cellpadding",
            "cellspacing", "char", "charoff", "charset", "checked", "cite", /* "class", */
            "clear", "cols", "colspan", "color", "compact", "coords", "datetime",
            "dir", "disabled", "enctype", "for", "frame", "headers", "height",
            "href", "hreflang", "hspace", /* "id", */ "ismap", "label", "lang",
            "longdesc", "maxlength", "media", "method", "multiple", "name",
            "nohref", "noshade", "nowrap", "prompt", "readonly", "rel", "rev",
            "rows", "rowspan", "rules", "scope", "selected", "shape", "size",
            "span", "src", "start", "style", "summary", "tabindex", "target", "title",
            "type", "usemap", "valign", "value", "vspace", "width",
            // HTML5
            "high", // <meter>
            "keytype", // <keygen>
            "list", // <input>
            "low", // <meter>
            "max", // <input>, <meter>, <progress>
            "min", // <input>, <meter>
            "novalidate", // <form>
            "open", // <details>
            "optimum", // <meter>
            "pattern", // <input>
            "placeholder", // <input>, <textarea>
            "pubdate", // <time>
            "radiogroup", // <menuitem>
            "required", // <input>, <select>, <textarea>
            "reversed", // <ol>
            "spellcheck", // Global attribute
            "step", // <input>
            "wrap", // <textarea>
            "challenge", // <keygen>
            "contenteditable", // Global attribute
            "draggable", // Global attribute
            "dropzone", // Global attribute
            "autocomplete", // <form>, <input>
            "autosave", // <input>
        };

        /// <summary>
        /// Gets or sets the HTML attributes that can contain a URI such as "href".
        /// </summary>
        /// <value>
        /// The URI attributes.
        /// </value>
        public ISet<string> UriAttributes { get; private set; }

        /// <summary>
        /// The default URI attributes.
        /// </summary>
        public static ISet<string> DefaultUriAttributes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "action", "background", "dynsrc", "href", "lowsrc", "src" };

        /// <summary>
        /// Gets or sets the allowed CSS properties such as "font" and "margin".
        /// </summary>
        /// <value>
        /// The allowed CSS properties.
        /// </value>
        public ISet<string> AllowedCssProperties { get; private set; }

        /// <summary>
        /// The default allowed CSS properties.
        /// </summary>
        public static ISet<string> DefaultAllowedCssProperties { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // CSS 3 properties <http://www.w3.org/TR/CSS/#properties>
            "background",
            "background-attachment",
            "background-clip",
            "background-color",
            "background-image",
            "background-origin",
            "background-position",
            "background-repeat",
            "background-repeat-x", // see https://github.com/mganss/HtmlSanitizer/issues/243
            "background-repeat-y",
            "background-size",
            "border",
            "border-bottom",
            "border-bottom-color",
            "border-bottom-left-radius",
            "border-bottom-right-radius",
            "border-bottom-style",
            "border-bottom-width",
            "border-collapse",
            "border-color",
            "border-image",
            "border-image-outset",
            "border-image-repeat",
            "border-image-slice",
            "border-image-source",
            "border-image-width",
            "border-left",
            "border-left-color",
            "border-left-style",
            "border-left-width",
            "border-radius",
            "border-right",
            "border-right-color",
            "border-right-style",
            "border-right-width",
            "border-spacing",
            "border-style",
            "border-top",
            "border-top-color",
            "border-top-left-radius",
            "border-top-right-radius",
            "border-top-style",
            "border-top-width",
            "border-width",
            "bottom",
            "caption-side",
            "clear",
            "clip",
            "color",
            "content",
            "counter-increment",
            "counter-reset",
            "cursor",
            "direction",
            "display",
            "empty-cells",
            "float",
            "font",
            "font-family",
            "font-feature-settings",
            "font-kerning",
            "font-language-override",
            "font-size",
            "font-size-adjust",
            "font-stretch",
            "font-style",
            "font-synthesis",
            "font-variant",
            "font-variant-alternates",
            "font-variant-caps",
            "font-variant-east-asian",
            "font-variant-ligatures",
            "font-variant-numeric",
            "font-variant-position",
            "font-weight",
            "height",
            "left",
            "letter-spacing",
            "line-height",
            "list-style",
            "list-style-image",
            "list-style-position",
            "list-style-type",
            "margin",
            "margin-bottom",
            "margin-left",
            "margin-right",
            "margin-top",
            "max-height",
            "max-width",
            "min-height",
            "min-width",
            "opacity",
            "orphans",
            "outline",
            "outline-color",
            "outline-offset",
            "outline-style",
            "outline-width",
            "overflow",
            "overflow-wrap",
            "overflow-x",
            "overflow-y",
            "padding",
            "padding-bottom",
            "padding-left",
            "padding-right",
            "padding-top",
            "page-break-after",
            "page-break-before",
            "page-break-inside",
            "quotes",
            "right",
            "table-layout",
            "text-align",
            "text-decoration",
            "text-decoration-color",
            "text-decoration-line",
            "text-decoration-skip",
            "text-decoration-style",
            "text-indent",
            "text-transform",
            "top",
            "unicode-bidi",
            "vertical-align",
            "visibility",
            "white-space",
            "widows",
            "width",
            "word-spacing",
            "z-index"
        };

        private Regex _disallowedCssPropertyValue;

        /// <summary>
        /// Gets or sets a regex that must not match for legal CSS property values.
        /// </summary>
        /// <value>
        /// The regex.
        /// </value>
        public Regex DisallowCssPropertyValue
        {
            get { return _disallowedCssPropertyValue ?? DefaultDisallowedCssPropertyValue; }
            set { _disallowedCssPropertyValue = value; }
        }

        /// <summary>
        /// The default allowed CSS classes.
        /// </summary>
        public static ISet<string> DefaultAllowedClasses { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
        public event EventHandler<PostProcessDomEventArgs> PostProcessDom;
        /// <summary>
        /// Occurs for every node after sanitizing.
        /// </summary>
        public event EventHandler<PostProcessNodeEventArgs> PostProcessNode;
        /// <summary>
        /// Occurs before a tag is removed.
        /// </summary>
        public event EventHandler<RemovingTagEventArgs> RemovingTag;
        /// <summary>
        /// Occurs before an attribute is removed.
        /// </summary>
        public event EventHandler<RemovingAttributeEventArgs> RemovingAttribute;
        /// <summary>
        /// Occurs before a style is removed.
        /// </summary>
        public event EventHandler<RemovingStyleEventArgs> RemovingStyle;
        /// <summary>
        /// Occurs before an at-rule is removed.
        /// </summary>
        public event EventHandler<RemovingAtRuleEventArgs> RemovingAtRule;
        /// <summary>
        /// Occurs before a comment is removed.
        /// </summary>
        public event EventHandler<RemovingCommentEventArgs> RemovingComment;
        /// <summary>
        /// Occurs before a CSS class is removed.
        /// </summary>
        public event EventHandler<RemovingCssClassEventArgs> RemovingCssClass;
        /// <summary>
        /// Occurs when a URL is being sanitized.
        /// </summary>
        public event EventHandler<FilterUrlEventArgs> FilterUrl;

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
        public static readonly Regex DefaultDisallowedCssPropertyValue = new Regex(@"[<>]", RegexOptions.Compiled);

        /// <summary>
        /// Raises the <see cref="E:RemovingCSSClass" /> event.
        /// </summary>
        /// <param name="e">The <see cref="RemovingCssClassEventArgs"/> instance containing the event data.</param>
        protected virtual void OnRemovingCssClass(RemovingCssClassEventArgs e)
        {
            RemovingCssClass?.Invoke(this, e);
        }

        /// <summary>
        /// Raises the <see cref="E:RemovingUrl" /> event.
        /// </summary>
        /// <param name="e">The <see cref="FilterUrlEventArgs"/> instance containing the event data.</param>
        protected virtual void OnFilteringUrl(FilterUrlEventArgs e)
        {
            FilterUrl?.Invoke(this, e);
        }

        /// <summary>
        /// Return all nested subnodes of a node.
        /// </summary>
        /// <param name="dom">The root node.</param>
        /// <returns>All nested subnodes.</returns>
        private static IEnumerable<INode> GetAllNodes(INode dom)
        {
            if (dom == null) yield break;

            foreach (var node in dom.ChildNodes)
            {
                yield return node;
                foreach (var child in GetAllNodes(node).Where(c => c != null))
                {
                    yield return child;
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
        public string Sanitize(string html, string baseUrl = "", IMarkupFormatter outputFormatter = null)
        {
            using (var dom = SanitizeDom(html, baseUrl))
            {
                var output = dom.Body.ChildNodes.ToHtml(outputFormatter ?? OutputFormatter);
                return output;
            }
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
            var dom = parser.ParseDocument("<html><body>" + html);

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
        public IHtmlDocument SanitizeDom(IHtmlDocument document, IHtmlElement context = null, string baseUrl = "")
        {
            DoSanitize(document, context ?? (IParentNode) document, baseUrl);
            return document;
        }

        /// <summary>
        /// Sanitizes the specified HTML document. Even if only a fragment is given, a whole document will be returned.
        /// </summary>
        /// <param name="html">The HTML document to sanitize.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
        /// <param name="outputFormatter">The formatter used to render the DOM. Using the <see cref="OutputFormatter"/> if null.</param>
        /// <returns>The sanitized HTML document.</returns>
        public string SanitizeDocument(string html, string baseUrl = "", IMarkupFormatter outputFormatter = null)
        {
            var parser = HtmlParserFactory();
            var dom = parser.ParseDocument(html);

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
        public string SanitizeDocument(Stream html, string baseUrl = "", IMarkupFormatter outputFormatter = null)
        {
            var parser = HtmlParserFactory();
            var dom = parser.ParseDocument(html);

            DoSanitize(dom, dom, baseUrl);

            var output = dom.ToHtml(outputFormatter ?? OutputFormatter);

            return output;
        }

        /// <summary>
        /// Creeates an instance of <see cref="HtmlParser"/>.
        /// </summary>
        /// <returns>An instance of <see cref="HtmlParser"/>.</returns>
        private static HtmlParser CreateParser()
        {
            return new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration().WithCss(new CssParserOptions
            {
                IsIncludingUnknownDeclarations = true,
                IsIncludingUnknownRules = true,
                IsToleratingInvalidSelectors = true,
            })));
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
                var e = new RemovingCommentEventArgs { Comment = comment };
                OnRemovingComment(e);
                if (!e.Cancel)
                    comment.Remove();
            }
        }

        private void DoSanitize(IHtmlDocument dom, IParentNode context, string baseUrl = "")
        {
            // remove disallowed tags
            foreach (var tag in context.QuerySelectorAll("*").Where(t => !IsAllowedTag(t)).ToList())
            {
                RemoveTag(tag, RemoveReason.NotAllowedTag);
            }

            SanitizeStyleSheets(dom, baseUrl);

            // cleanup attributes
            foreach (var tag in context.QuerySelectorAll("*").ToList())
            {
                // remove disallowed attributes
                foreach (var attribute in tag.Attributes.Where(a => !IsAllowedAttribute(a)).ToList())
                {
                    RemoveAttribute(tag, attribute, RemoveReason.NotAllowedAttribute);
                }

                // sanitize URLs in URL-marked attributes
                foreach (var attribute in tag.Attributes.Where(IsUriAttribute).ToList())
                {
                    var url = SanitizeUrl(attribute.Value, baseUrl);
                    if (url == null)
                        RemoveAttribute(tag, attribute, RemoveReason.NotAllowedUrlValue);
                    else
                        tag.SetAttribute(attribute.Name, url);
                }

                // sanitize the style attribute
                var oldStyleEmpty = string.IsNullOrEmpty(tag.GetAttribute("style"));
                SanitizeStyle(tag, baseUrl);

                // sanitize the value of the attributes
                foreach (var attribute in tag.Attributes.ToList())
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

                            if (!tag.ClassList.Any())
                                RemoveAttribute(tag, attribute, RemoveReason.ClassAttributeEmpty);
                        }
                        else if (!oldStyleEmpty && attribute.Name == "style" && string.IsNullOrEmpty(attribute.Value))
                        {
                            RemoveAttribute(tag, attribute, RemoveReason.StyleAttributeEmpty);
                        }
                    }
                }
            }

            RemoveComments(context as INode);

            DoPostProcess(dom, context as INode);
        }

        private void SanitizeStyleSheets(IHtmlDocument dom, string baseUrl)
        {
            foreach (var styleSheet in dom.StyleSheets.OfType<ICssStyleSheet>())
            {
                var styleTag = styleSheet.OwnerNode;

                for (int i = 0; i < styleSheet.Rules.Length;)
                {
                    var rule = styleSheet.Rules[i];
                    if (!SanitizeStyleRule(rule, styleTag, baseUrl) && RemoveAtRule(styleTag, rule))
                        styleSheet.RemoveAt(i);
                    else i++;
                }

                styleTag.InnerHtml = styleSheet.ToCss().Replace("<", "\\3c");
            }
        }

        private bool SanitizeStyleRule(ICssRule rule, IElement styleTag, string baseUrl)
        {
            if (!AllowedAtRules.Contains(rule.Type)) return false;

            if (rule is ICssStyleRule styleRule)
            {
                SanitizeStyleDeclaration(styleTag, styleRule.Style, baseUrl);
            }
            else
            {
                if (rule is ICssGroupingRule groupingRule)
                {
                    for (int i = 0; i < groupingRule.Rules.Length;)
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
                    foreach (var childRule in keyFramesRule.Rules.OfType<ICssKeyframeRule>().ToList())
                    {
                        if (!SanitizeStyleRule(childRule, styleTag, baseUrl) && RemoveAtRule(styleTag, childRule))
                            keyFramesRule.Remove(childRule.KeyText);
                    }
                }
                else if (rule is ICssKeyframeRule keyFrameRule)
                {
                    SanitizeStyleDeclaration(styleTag, keyFrameRule.Style, baseUrl);
                }
            }

            return true;
        }

        /// <summary>
        /// Performs post processing on all nodes in the document.
        /// </summary>
        /// <param name="dom">The HTML document.</param>
        /// <param name="context">The node within which to post process all nodes.</param>
        private void DoPostProcess(IHtmlDocument dom, INode context)
        {
            if (PostProcessNode != null)
            {
                dom.Normalize();
                var nodes = GetAllNodes(context).ToList();

                foreach (var node in nodes)
                {
                    var e = new PostProcessNodeEventArgs { Document = dom, Node = node };
                    OnPostProcessNode(e);
                    if (e.ReplacementNodes.Any())
                    {
                        ((IChildNode)node).Replace(e.ReplacementNodes.ToArray());
                    }
                }
            }

            if (PostProcessDom != null)
            {
                var e = new PostProcessDomEventArgs { Document = dom };
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

        // from http://genshi.edgewall.org/
        private static readonly Regex CssUnicodeEscapes = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
        private static readonly Regex CssComments = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
        // IE6 <http://heideri.ch/jso/#80>
        private static readonly Regex CssExpression = new Regex(@"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);
        private static readonly Regex CssUrl = new Regex(@"[Uu][Rr\u0280][Ll\u029F]\s*\(\s*(['""]?)\s*([^'"")\s]+)\s*(['""]?)\s*", RegexOptions.Compiled);

        /// <summary>
        /// Sanitizes the style.
        /// </summary>
        /// <param name="element">The element.</param>
        /// <param name="baseUrl">The base URL.</param>
        protected void SanitizeStyle(IElement element, string baseUrl)
        {
            // filter out invalid CSS declarations
            // see https://github.com/AngleSharp/AngleSharp/issues/101
            var attribute = element.GetAttribute("style");
            if (attribute == null) return;
            if (element.GetStyle() == null)
            {
                element.RemoveAttribute("style");
                return;
            }
            element.SetAttribute("style", element.GetStyle().ToCss());

            var styles = element.GetStyle();
            if (styles == null || styles.Length == 0) return;

            SanitizeStyleDeclaration(element, styles, baseUrl);
        }

        private void SanitizeStyleDeclaration(IElement element, ICssStyleDeclaration styles, string baseUrl)
        {
            var removeStyles = new List<Tuple<ICssProperty, RemoveReason>>();
            var setStyles = new Dictionary<string, string>();

            foreach (var style in styles)
            {
                var key = DecodeCss(style.Name);
                var val = DecodeCss(style.Value);

                if (!AllowedCssProperties.Contains(key))
                {
                    removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(style, RemoveReason.NotAllowedStyle));
                    continue;
                }

                if (CssExpression.IsMatch(val) || DisallowCssPropertyValue.IsMatch(val))
                {
                    removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(style, RemoveReason.NotAllowedValue));
                    continue;
                }

                var urls = CssUrl.Matches(val);

                if (urls.Count > 0)
                {
                    if (urls.Cast<Match>().Any(m => SanitizeUrl(m.Groups[2].Value, baseUrl) == null))
                        removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(style, RemoveReason.NotAllowedUrlValue));
                    else
                    {
                        var s = CssUrl.Replace(val, m => "url(" + m.Groups[1].Value + SanitizeUrl(m.Groups[2].Value, baseUrl) + m.Groups[3].Value);
                        if (s != val)
                        {
                            if (key != style.Name)
                            {
                                removeStyles.Add(new Tuple<ICssProperty, RemoveReason>(style, RemoveReason.NotAllowedUrlValue));
                            }
                            setStyles[key] = s;
                        }
                    }
                }
            }

            foreach (var style in setStyles)
            {
                styles.SetProperty(style.Key, style.Value);
            }

            foreach (var style in removeStyles)
            {
                RemoveStyle(element, styles, style.Item1, style.Item2);
            }
        }

        /// <summary>
        /// Decodes CSS unicode escapes and removes comments.
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

        private static readonly Regex SchemeRegex = new Regex(@"^\s*([^\/#]*?)(?:\:|&#0*58|&#x0*3a)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Tries to create a safe <see cref="Iri"/> object from a string.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <returns>The <see cref="Iri"/> object or null if no safe <see cref="Iri"/> can be created.</returns>
        protected Iri GetSafeIri(string url)
        {
            var schemeMatch = SchemeRegex.Match(url);

            if (schemeMatch.Success)
            {
                var scheme = schemeMatch.Groups[1].Value;
                return AllowedSchemes.Contains(scheme, StringComparer.OrdinalIgnoreCase) ? new Iri { Value = url, Scheme = scheme } : null;
            }

            return new Iri { Value = url };
        }

        /// <summary>
        /// Sanitizes a URL.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against (empty or null for no resolution).</param>
        /// <returns>The sanitized URL or null if no safe URL can be created.</returns>
        protected virtual string SanitizeUrl(string url, string baseUrl)
        {
            var iri = GetSafeIri(url);

            if (iri != null && !iri.IsAbsolute && !string.IsNullOrEmpty(baseUrl))
            {
                // resolve relative uri
                if (Uri.TryCreate(baseUrl, UriKind.Absolute, out Uri baseUri))
                {
                    try
                    {
                        return new Uri(baseUri, iri.Value).AbsoluteUri;
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (UriFormatException)
                    {
                        iri = null;
                    }
#pragma warning restore CA1031 // Do not catch general exception types
                }
                else iri = null;
            }

            var e = new FilterUrlEventArgs { OriginalUrl = url, SanitizedUrl = iri?.Value };
            OnFilteringUrl(e);

            return e.SanitizedUrl;
        }

        /// <summary>
        /// Removes a tag from the document.
        /// </summary>
        /// <param name="tag">Tag to be removed</param>
        /// <param name="reason">Reason for removal</param>
        private void RemoveTag(IElement tag, RemoveReason reason)
        {
            var e = new RemovingTagEventArgs { Tag = tag, Reason = reason };
            OnRemovingTag(e);
            if (!e.Cancel)
            {
                if (KeepChildNodes && tag.HasChildNodes)
                    tag.Replace(tag.ChildNodes.ToArray());
                else
                    tag.Remove();
            }
        }

        /// <summary>
        /// Removes an attribute from the document.
        /// </summary>
        /// <param name="tag">Tag the attribute belongs to</param>
        /// <param name="attribute">Attribute to be removed</param>
        /// <param name="reason">Reason for removal</param>
        private void RemoveAttribute(IElement tag, IAttr attribute, RemoveReason reason)
        {
            var e = new RemovingAttributeEventArgs { Tag = tag, Attribute = attribute, Reason = reason };
            OnRemovingAttribute(e);
            if (!e.Cancel) tag.RemoveAttribute(attribute.Name);
        }

        /// <summary>
        /// Removes a style from the document.
        /// </summary>
        /// <param name="tag">Tag the style belongs to</param>
        /// <param name="styles">Style rule that contains the style to be removed</param>
        /// <param name="style">Style to be removed</param>
        /// <param name="reason">Reason for removal</param>
        private void RemoveStyle(IElement tag, ICssStyleDeclaration styles, ICssProperty style, RemoveReason reason)
        {
            var e = new RemovingStyleEventArgs { Tag = tag, Style = style, Reason = reason };
            OnRemovingStyle(e);
            if (!e.Cancel) styles.RemoveProperty(style.Name);
        }

        /// <summary>
        /// Removes an at-rule from the document.
        /// </summary>
        /// <param name="tag">Tag the style belongs to</param>
        /// <param name="rule">Rule to be removed</param>
        /// <returns>true, if the rule can be removed; false, otherwise.</returns>
        private bool RemoveAtRule(IElement tag, ICssRule rule)
        {
            var e = new RemovingAtRuleEventArgs { Tag = tag, Rule = rule };
            OnRemovingAtRule(e);
            return !e.Cancel;
        }

        /// <summary>
        /// Removes a CSS class from a class attribute.
        /// </summary>
        /// <param name="tag">Tag the style belongs to</param>
        /// <param name="cssClass">Class to be removed</param>
        /// <param name="reason">Reason for removal</param>
        private void RemoveCssClass(IElement tag, string cssClass, RemoveReason reason)
        {
            var e = new RemovingCssClassEventArgs { Tag = tag, CssClass = cssClass, Reason = reason };
            OnRemovingCssClass(e);
            if (!e.Cancel) tag.ClassList.Remove(cssClass);
        }
    }
}
