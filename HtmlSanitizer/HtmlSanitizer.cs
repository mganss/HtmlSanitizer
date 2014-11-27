using CsQuery;
using CsQuery.ExtensionMethods.Internal;
using CsQuery.Output;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Ganss.XSS
{
    /// <summary>
    /// Cleans HTML fragments from constructs that can lead to <a href="https://en.wikipedia.org/wiki/Cross-site_scripting">XSS attacks</a>.
    /// </summary>
    /// <remarks>
    /// XSS attacks can occur at several levels within an HTML fragment:
    /// <list type="bullet">
    /// <item>HTML Tags (e.g. the &lt;script&gt; tag)</item>
    /// <item>HTML attributes (e.g. the "onload" attribute)</item>
    /// <item>CSS styles (url property values)</item>
    /// <item>malformed HTML or HTML that exploits parser bugs in specific browsers</item>
    /// </list>
    /// <para>
    /// The HtmlSanitizer class addresses all of these possible attack vectors by using an HTML parser that is based on the one used
    /// in the Gecko browser engine (see <a href="https://github.com/jamietre/CsQuery">CsQuery</a>).
    /// </para>
    /// <para>
    /// In order to facilitate different use cases, HtmlSanitizer can be customized at the levels mentioned above:
    /// <list type="bullet">
    /// <item>You can specify the allowed HTML tags through the property <see cref="AllowedTags"/>. All other tags will be stripped.</item>
    /// <item>You can specify the allowed HTML attributes through the property <see cref="AllowedAttributes"/>. All other attributes will be stripped.</item>
    /// <item>You can specify the allowed CSS property names through the property <see cref="AllowedCssProperties"/>. All other styles will be stripped.</item>
    /// <item>You can specify the allowed URI schemes through the property <see cref="AllowedCssProperties"/>. All other URIs will be stripped.</item>
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
    public class HtmlSanitizer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HtmlSanitizer"/> class.
        /// </summary>
        /// <param name="allowedTags">The allowed tag names such as "a" and "div". When <c>null</c>, uses <see cref="DefaultAllowedTags"/></param>
        /// <param name="allowedSchemes">The allowed HTTP schemes such as "http" and "https". When <c>null</c>,  uses <see cref="DefaultAllowedSchemes"/></param>
        /// <param name="allowedAttributes">The allowed HTML attributes such as "href" and "alt". When <c>null</c>, uses <see cref="DefaultAllowedAttributes"/></param>
        /// <param name="uriAttributes">the HTML attributes that can contain a URI such as "href". When <c>null</c>, uses <see cref="DefaultUriAttributes"/></param>
        /// <param name="allowedCssProperties">the allowed CSS properties such as "font" and "margin". When <c>null</c>, uses <see cref="DefaultAllowedCssProperties"/></param>
        public HtmlSanitizer(IEnumerable<string> allowedTags = null, IEnumerable<string> allowedSchemes = null,
            IEnumerable<string> allowedAttributes = null, IEnumerable<string> uriAttributes = null, IEnumerable<string> allowedCssProperties = null)
        {
            AllowedTags = new HashSet<string>(allowedTags ?? DefaultAllowedTags, StringComparer.OrdinalIgnoreCase);
            AllowedSchemes = new HashSet<string>(allowedSchemes ?? DefaultAllowedSchemes, StringComparer.OrdinalIgnoreCase);
            AllowedAttributes = new HashSet<string>(allowedAttributes ?? DefaultAllowedAttributes, StringComparer.OrdinalIgnoreCase);
            UriAttributes = new HashSet<string>(uriAttributes ?? DefaultUriAttributes, StringComparer.OrdinalIgnoreCase);
            AllowedCssProperties = new HashSet<string>(allowedCssProperties ?? DefaultAllowedCssProperties, StringComparer.OrdinalIgnoreCase);
        }

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
        public static readonly ISet<string> DefaultAllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" };

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
        public static readonly ISet<string> DefaultAllowedTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { 
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
            "details", "summary", "menuitem"
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
        public static readonly ISet<string> DefaultAllowedAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { 
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
        public static readonly ISet<string> DefaultUriAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "action", "background", "dynsrc", "href", "lowsrc", "src" };

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
        public static readonly ISet<string> DefaultAllowedCssProperties = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { 
            // CSS 3 properties <http://www.w3.org/TR/CSS/#properties>
            "background", "background-attachment", "background-color",
            "background-image", "background-position", "background-repeat",
            "border", "border-bottom", "border-bottom-color",
            "border-bottom-style", "border-bottom-width", "border-collapse",
            "border-color", "border-left", "border-left-color",
            "border-left-style", "border-left-width", "border-right",
            "border-right-color", "border-right-style", "border-right-width",
            "border-spacing", "border-style", "border-top", "border-top-color",
            "border-top-style", "border-top-width", "border-width", "bottom",
            "caption-side", "clear", "clip", "color", "content",
            "counter-increment", "counter-reset", "cursor", "direction", "display",
            "empty-cells", "float", "font", "font-family", "font-size",
            "font-style", "font-variant", "font-weight", "height", "left",
            "letter-spacing", "line-height", "list-style", "list-style-image",
            "list-style-position", "list-style-type", "margin", "margin-bottom",
            "margin-left", "margin-right", "margin-top", "max-height", "max-width",
            "min-height", "min-width", "opacity", "orphans", "outline",
            "outline-color", "outline-style", "outline-width", "overflow",
            "padding", "padding-bottom", "padding-left", "padding-right",
            "padding-top", "page-break-after", "page-break-before",
            "page-break-inside", "quotes", "right", "table-layout",
            "text-align", "text-decoration", "text-indent", "text-transform",
            "top", "unicode-bidi", "vertical-align", "visibility", "white-space",
            "widows", "width", "word-spacing", "z-index" };

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
        /// Raises the <see cref="E:RemovingTag" /> event.
        /// </summary>
        /// <param name="e">The <see cref="RemovingTagEventArgs"/> instance containing the event data.</param>
        protected virtual void OnRemovingTag(RemovingTagEventArgs e)
        {
            if (RemovingTag != null) RemovingTag(this, e);
        }

        /// <summary>
        /// Raises the <see cref="E:RemovingAttribute" /> event.
        /// </summary>
        /// <param name="e">The <see cref="RemovingAttributeEventArgs"/> instance containing the event data.</param>
        protected virtual void OnRemovingAttribute(RemovingAttributeEventArgs e)
        {
            if (RemovingAttribute != null) RemovingAttribute(this, e);
        }

        /// <summary>
        /// Raises the <see cref="E:RemovingStyle" /> event.
        /// </summary>
        /// <param name="e">The <see cref="RemovingStyleEventArgs"/> instance containing the event data.</param>
        protected virtual void OnRemovingStyle(RemovingStyleEventArgs e)
        {
            if (RemovingStyle != null) RemovingStyle(this, e);
        }

        /// <summary>
        /// The default regex for disallowed CSS property values.
        /// </summary>
        public static readonly Regex DefaultDisallowedCssPropertyValue = new Regex(@"[<>]", RegexOptions.Compiled);

        /// <summary>
        /// The regex for Javascript includes (see https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#.26_JavaScript_includes)
        /// </summary>
        protected static readonly Regex JSInclude = new Regex(@"\s*&{");

        /// <summary>
        /// Sanitizes the specified HTML.
        /// </summary>
        /// <param name="html">The HTML to sanitize.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
        /// <param name="outputFormatter">The CsQuery output formatter used to render the DOM. Using the default formatter if null.</param>
        /// <returns>The sanitized HTML.</returns>
        public string Sanitize(string html, string baseUrl = "", IOutputFormatter outputFormatter = null)
        {
            var dom = CQ.Create(html);

            foreach (var tag in dom["*"].Not(string.Join(",", AllowedTags)).ToList())
            {
                var e = new RemovingTagEventArgs { Tag = tag };
                OnRemovingTag(e);
                if (!e.Cancel) tag.Remove();
            }

            foreach (var tag in dom["*"])
            {
                foreach (var attribute in tag.Attributes.Where(a => !AllowedAttributes.Contains(a.Key)).ToList())
                {
                    if (AllowDataAttributes && attribute.Key != null && attribute.Key.StartsWith("data-", StringComparison.CurrentCultureIgnoreCase))
                    {
                        continue;
                    }

                    RemoveAttribute(tag, attribute);
                }

                foreach (var attribute in tag.Attributes.Where(a => UriAttributes.Contains(a.Key)).ToList())
                {
                    var url = SanitizeUrl(attribute.Value, baseUrl);
                    if (url == null)
                    {
                        RemoveAttribute(tag, attribute);
                    }
                    else
                        tag.SetAttribute(attribute.Key, url);
                }

                SanitizeStyle(tag.Style, baseUrl);

                foreach (var attribute in tag.Attributes.ToList())
                {
                    if (JSInclude.IsMatch(attribute.Value))
                        RemoveAttribute(tag, attribute);

                    var val = attribute.Value;
                    if (val.Contains('<')) { val = val.Replace("<", "&lt;"); tag.SetAttribute(attribute.Key, val); }
                    if (val.Contains('>')) { val = val.Replace(">", "&gt;"); tag.SetAttribute(attribute.Key, val); }
                }
            }

            if (outputFormatter == null)
                outputFormatter = new FormatDefault(DomRenderingOptions.RemoveComments | DomRenderingOptions.QuoteAllAttributes, HtmlEncoders.Default);

            var output = dom.Render(outputFormatter);

            return output;
        }

        private void RemoveAttribute(IDomObject tag, KeyValuePair<string, string> attribute)
        {
            var e = new RemovingAttributeEventArgs { Attribute = attribute };
            OnRemovingAttribute(e);
            if (!e.Cancel) tag.RemoveAttribute(attribute.Key);
        }

        // from http://genshi.edgewall.org/
        private static readonly Regex CssUnicodeEscapes = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
        private static readonly Regex CssComments = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
        // IE6 <http://heideri.ch/jso/#80>
        private static readonly Regex CssExpression = new Regex(@"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);
        private static readonly Regex CssUrl = new Regex(@"[Uu][Rr\u0280][Ll\u029F]\s*\(\s*['""]?\s*([^'"")]+)", RegexOptions.Compiled);

        /// <summary>
        /// Sanitizes the style.
        /// </summary>
        /// <param name="styles">The styles.</param>
        /// <param name="baseUrl">The base URL.</param>
        protected void SanitizeStyle(CsQuery.Implementation.CSSStyleDeclaration styles, string baseUrl)
        {
            if (styles == null || !styles.Any()) return;

            var removeStyles = new List<KeyValuePair<string, string>>();
            var setStyles = new Dictionary<string, string>();

            foreach (var style in styles)
            {
                var key = DecodeCss(style.Key);
                var val = DecodeCss(style.Value);

                if (!AllowedCssProperties.Contains(key) || CssExpression.IsMatch(val) || DisallowCssPropertyValue.IsMatch(val))
                    removeStyles.Add(style);
                else
                {
                    var urls = CssUrl.Matches(val);

                    if (urls.Count > 0)
                    {
                        if (urls.Cast<Match>().Any(m => GetSafeUri(m.Groups[1].Value) == null))
                            removeStyles.Add(style);
                        else
                        {
                            var s = CssUrl.Replace(val, m => "url(" + SanitizeUrl(m.Groups[1].Value, baseUrl));
                            if (s != val)
                            {
                                if (key != style.Key) removeStyles.Add(style);
                                setStyles[key] = s;
                            }
                        }
                    }
                }
            }

            foreach (var style in removeStyles)
            {
                var e = new RemovingStyleEventArgs { Style = style };
                OnRemovingStyle(e);
                if (!e.Cancel) styles.RemoveStyle(style.Key);
            }

            foreach (var kvp in setStyles)
            {
                styles.SetStyle(kvp.Key, kvp.Value);
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

        /// <summary>
        /// Tries to create a safe <see cref="Uri"/> object from a string.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <returns>The <see cref="Uri"/> object or null if no safe <see cref="Uri"/> can be created.</returns>
        protected Uri GetSafeUri(string url)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.RelativeOrAbsolute, out uri)
                || !uri.IsWellFormedOriginalString() && !IsWellFormedRelativeUri(uri)
                || uri.IsAbsoluteUri && !AllowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase)
                || !uri.IsAbsoluteUri && url.Contains(':'))
                return null;

            return uri;
        }

        private static Uri _exampleUri = new Uri("http://www.example.com/");
        private static bool IsWellFormedRelativeUri(Uri uri)
        {
            if (uri.IsAbsoluteUri) return false;

            Uri absoluteUri;
            if (!Uri.TryCreate(_exampleUri, uri, out absoluteUri)) return false;
            var wellFormed = absoluteUri.IsWellFormedOriginalString();
            return wellFormed;
        }

        /// <summary>
        /// Sanitizes a URL.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against (empty or null for no resolution).</param>
        /// <returns>The sanitized URL or null if no safe URL can be created.</returns>
        protected string SanitizeUrl(string url, string baseUrl)
        {
            var uri = GetSafeUri(url);

            if (uri == null) return null;

            if (!uri.IsAbsoluteUri && !string.IsNullOrEmpty(baseUrl))
            {
                // resolve relative uri
                Uri baseUri;
                if (Uri.TryCreate(baseUrl, UriKind.Absolute, out baseUri))
                    uri = new Uri(baseUri, uri.ToString());
                else return null;
            }

            return uri.ToString();
        }
    }
}
