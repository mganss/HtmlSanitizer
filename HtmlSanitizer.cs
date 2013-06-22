using CsQuery;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Html
{
    public class HtmlSanitizer
    {
        private IEnumerable<string> _allowedSchemes;

        /// <summary>
        /// Gets or sets the allowed HTTP schemes such as "http" and "https".
        /// </summary>
        /// <value>
        /// The allowed HTTP schemes.
        /// </value>
        public IEnumerable<string> AllowedSchemes
        {
            get { return _allowedSchemes ?? DefaultAllowedSchemes; }
            set { _allowedSchemes = value; }
        }

        /// <summary>
        /// The default allowed HTTP schemes.
        /// </summary>
        public static readonly IEnumerable<string> DefaultAllowedSchemes = new[] { "http", "https" };

        private IEnumerable<string> _allowedTags;

        /// <summary>
        /// Gets or sets the allowed HTML tag names such as "a" and "div".
        /// </summary>
        /// <value>
        /// The allowed tag names.
        /// </value>
        public IEnumerable<string> AllowedTags
        {
            get { return _allowedTags ?? DefaultAllowedTags; }
            set { _allowedTags = value; }
        }

        /// <summary>
        /// The default allowed HTML tag names.
        /// </summary>
        public static readonly IEnumerable<string> DefaultAllowedTags = new[] { "a", "abbr", "acronym", "address", "area", "b",
            "big", "blockquote", "br", "button", "caption", "center", "cite",
            "code", "col", "colgroup", "dd", "del", "dfn", "dir", "div", "dl", "dt",
            "em", "fieldset", "font", "form", "h1", "h2", "h3", "h4", "h5", "h6",
            "hr", "i", "img", "input", "ins", "kbd", "label", "legend", "li", "map",
            "menu", "ol", "optgroup", "option", "p", "pre", "q", "s", "samp",
            "select", "small", "span", "strike", "strong", "sub", "sup", "table",
            "tbody", "td", "textarea", "tfoot", "th", "thead", "tr", "tt", "u",
            "ul", "var" };

        /// <summary>
        /// Gets or sets the allowed HTML attributes such as "href" and "alt".
        /// </summary>
        /// <value>
        /// The allowed HTML attributes.
        /// </value>
        public IEnumerable<string> AllowedAttributes
        {
            get { return AllowedAttributesSet.ToArray(); }
            set
            {
                AllowedAttributesSet = new HashSet<string>(value, StringComparer.OrdinalIgnoreCase);
            }
        }

        private HashSet<string> _allowedAttributesSet;

        private HashSet<string> AllowedAttributesSet
        {
            get { return _allowedAttributesSet ?? DefaultAllowedAttributesSet; }
            set { _allowedAttributesSet = value; }
        }

        /// <summary>
        /// The default allowed HTML attributes.
        /// </summary>
        public static readonly IEnumerable<string> DefaultAllowedAttributes = new[] { "abbr", "accept", "accept-charset", "accesskey",
            "action", "align", "alt", "axis", "bgcolor", "border", "cellpadding",
            "cellspacing", "char", "charoff", "charset", "checked", "cite", /* "class", */
            "clear", "cols", "colspan", "color", "compact", "coords", "datetime",
            "dir", "disabled", "enctype", "for", "frame", "headers", "height",
            "href", "hreflang", "hspace", /* "id", */ "ismap", "label", "lang",
            "longdesc", "maxlength", "media", "method", "multiple", "name",
            "nohref", "noshade", "nowrap", "prompt", "readonly", "rel", "rev",
            "rows", "rowspan", "rules", "scope", "selected", "shape", "size",
            "span", "src", "start", "style", "summary", "tabindex", "target", "title",
            "type", "usemap", "valign", "value", "vspace", "width" };
        private static HashSet<string> DefaultAllowedAttributesSet = new HashSet<string>(DefaultAllowedAttributes, StringComparer.OrdinalIgnoreCase);

        private IEnumerable<string> _uriAttributes;

        /// <summary>
        /// Gets or sets the HTML attributes that can contain a URI.
        /// </summary>
        /// <value>
        /// The URI attributes.
        /// </value>
        public IEnumerable<string> UriAttributes
        {
            get { return _uriAttributes ?? DefaultUriAttributes; }
            set { _uriAttributes = value; }
        }

        /// <summary>
        /// The default URI attributes.
        /// </summary>
        public static readonly IEnumerable<string> DefaultUriAttributes = new[] { "action", "background", "dynsrc", "href", "lowsrc", "src" };

        /// <summary>
        /// Gets or sets the allowed CSS properties.
        /// </summary>
        /// <value>
        /// The allowed CSS properties.
        /// </value>
        public IEnumerable<string> AllowedCssProperties
        {
            get { return AllowedCssPropertiesSet.ToArray(); }
            set
            {
                AllowedCssPropertiesSet = new HashSet<string>(value, StringComparer.OrdinalIgnoreCase);
            }
        }

        private HashSet<string> _allowedCssPropertiesSet;

        private HashSet<string> AllowedCssPropertiesSet
        {
            get { return _allowedCssPropertiesSet ?? DefaultAllowedCssPropertiesSet; }
            set { _allowedCssPropertiesSet = value; }
        }

        /// <summary>
        /// The default allowed CSS properties.
        /// </summary>
        public static readonly IEnumerable<string> DefaultAllowedCssProperties = new[] { 
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
        private static HashSet<string> DefaultAllowedCssPropertiesSet = new HashSet<string>(DefaultAllowedCssProperties, StringComparer.OrdinalIgnoreCase);

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
        /// <returns>The sanitized HTML.</returns>
        public string Sanitize(string html, string baseUrl = "")
        {
            var dom = CQ.Create(html);

            dom["*"].Not(string.Join(",", AllowedTags.ToArray())).Remove();
            foreach (var tag in dom["*"])
            {
                foreach (var attribute in tag.Attributes.Where(a => !AllowedAttributesSet.Contains(a.Key)).ToList())
                    tag.RemoveAttribute(attribute.Key);

                foreach (var attribute in tag.Attributes.Where(a => UriAttributes.Contains(a.Key)).ToList())
                {
                    var url = SanitizeUrl(attribute.Value, baseUrl);
                    if (url == null)
                        tag.RemoveAttribute(attribute.Key);
                    else
                        tag.SetAttribute(attribute.Key, url);
                }

                SanitizeStyle(tag.Style, baseUrl);

                foreach (var attribute in tag.Attributes.ToList())
                {
                    if (JSInclude.IsMatch(attribute.Value))
                        tag.RemoveAttribute(attribute.Key);

                    var val = attribute.Value;
                    if (val.Contains('<')) { val = val.Replace("<", "&lt;"); tag.SetAttribute(attribute.Key, val); }
                    if (val.Contains('>')) { val = val.Replace(">", "&gt;"); tag.SetAttribute(attribute.Key, val); }
                }
            }

            var output = dom.Render(DomRenderingOptions.RemoveComments | DomRenderingOptions.QuoteAllAttributes);

            return output;
        }

        // frolm http://genshi.edgewall.org/
        protected static readonly Regex CssUnicodeEscapes = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
        protected static readonly Regex CssComments = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
        // IE6 <http://heideri.ch/jso/#80>
        protected static readonly Regex CssExpression = new Regex(@"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);
        protected static readonly Regex CssUrl = new Regex(@"[Uu][Rr\u0280][Ll\u029F]\s*\(\s*['""]?\s*([^'"")]+)", RegexOptions.Compiled);

        /// <summary>
        /// Sanitizes the style.
        /// </summary>
        /// <param name="styles">The styles.</param>
        /// <param name="baseUrl">The base URL.</param>
        protected void SanitizeStyle(CsQuery.Implementation.CSSStyleDeclaration styles, string baseUrl)
        {
            if (styles == null || !styles.Any()) return;

            var removeStyles = new List<string>();
            var setStyles = new Dictionary<string, string>();

            foreach (var style in styles)
            {
                var key = DecodeCss(style.Key);
                var val = DecodeCss(style.Value);

                if (!AllowedCssPropertiesSet.Contains(key) || CssExpression.IsMatch(val) || DisallowCssPropertyValue.IsMatch(val))
                    removeStyles.Add(style.Key);
                else
                {
                    var urls = CssUrl.Matches(val);

                    if (urls.Count > 0)
                    {
                        if (urls.Cast<Match>().Any(m => GetSafeUri(m.Groups[1].Value) == null))
                            removeStyles.Add(style.Key);
                        else
                        {
                            var s = CssUrl.Replace(val, m => "url(" + SanitizeUrl(m.Groups[1].Value, baseUrl));
                            if (s != val)
                            {
                                if (key != style.Key) removeStyles.Add(style.Key);
                                setStyles[key] = s;
                            }
                        }
                    }
                }
            }

            foreach (var key in removeStyles)
            {
                styles.RemoveStyle(key);
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
