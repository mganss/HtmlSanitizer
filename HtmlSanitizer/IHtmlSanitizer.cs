using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using CsQuery.Output;

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
    public interface IHtmlSanitizer
    {
        /// <summary>
        /// Gets or sets the allowed HTTP schemes such as "http" and "https".
        /// </summary>
        /// <value>
        /// The allowed HTTP schemes.
        /// </value>
        ISet<string> AllowedSchemes { get; }

        /// <summary>
        /// Gets or sets the allowed HTML tag names such as "a" and "div".
        /// </summary>
        /// <value>
        /// The allowed tag names.
        /// </value>
        ISet<string> AllowedTags { get; }

        /// <summary>
        /// Gets or sets the allowed HTML attributes such as "href" and "alt".
        /// </summary>
        /// <value>
        /// The allowed HTML attributes.
        /// </value>
        ISet<string> AllowedAttributes { get; }

        /// <summary>
        /// Allow all HTML5 data attributes; the attributes prefixed with data-
        /// </summary>
        bool AllowDataAttributes { get; set; }

        /// <summary>
        /// Gets or sets the HTML attributes that can contain a URI such as "href".
        /// </summary>
        /// <value>
        /// The URI attributes.
        /// </value>
        ISet<string> UriAttributes { get; }

        /// <summary>
        /// Gets or sets the allowed CSS properties such as "font" and "margin".
        /// </summary>
        /// <value>
        /// The allowed CSS properties.
        /// </value>
        ISet<string> AllowedCssProperties { get; }

        /// <summary>
        /// Gets or sets a regex that must not match for legal CSS property values.
        /// </summary>
        /// <value>
        /// The regex.
        /// </value>
        Regex DisallowCssPropertyValue { get; set; }

        /// <summary>
        /// Occurs for every node after sanitizing.
        /// </summary>
        event EventHandler<PostProcessNodeEventArgs> PostProcessNode;

        /// <summary>
        /// Occurs before a tag is removed.
        /// </summary>
        event EventHandler<RemovingTagEventArgs> RemovingTag;

        /// <summary>
        /// Occurs before an attribute is removed.
        /// </summary>
        event EventHandler<RemovingAttributeEventArgs> RemovingAttribute;

        /// <summary>
        /// Occurs before a style is removed.
        /// </summary>
        event EventHandler<RemovingStyleEventArgs> RemovingStyle;

        /// <summary>
        /// Sanitizes the specified HTML.
        /// </summary>
        /// <param name="html">The HTML to sanitize.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
        /// <param name="outputFormatter">The CsQuery output formatter used to render the DOM. Using the default formatter if null.</param>
        /// <returns>The sanitized HTML.</returns>
        string Sanitize(string html, string baseUrl = "", IOutputFormatter outputFormatter = null);
    }
}