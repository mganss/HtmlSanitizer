using AngleSharp;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Ganss.XSS
{
    /// <summary>
    /// Enables an inheriting class to implement an HtmlSanitizer class, which cleans HTML documents and fragments
    /// from constructs that can lead to <a href="https://en.wikipedia.org/wiki/Cross-site_scripting">XSS attacks</a>.
    /// </summary>
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

        /// Gets or sets the allowed CSS classes.
        /// </summary>
        /// <value>
        /// The allowed CSS classes.
        /// </value>
        ISet<string> AllowedCssClasses { get; }

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
        /// Occurs before a CSS class is removed.
        /// </summary>
        event EventHandler<RemovingCssClassEventArgs> RemovingCssClass;

        /// <summary>
        /// Sanitizes the specified HTML.
        /// </summary>
        /// <param name="html">The HTML to sanitize.</param>
        /// <param name="baseUrl">The base URL relative URLs are resolved against. No resolution if empty.</param>
        /// <param name="outputFormatter">The formatter used to render the DOM. Using the default formatter if null.</param>
        /// <returns>The sanitized HTML.</returns>
        string Sanitize(string html, string baseUrl = "", IMarkupFormatter outputFormatter = null);
    }
}