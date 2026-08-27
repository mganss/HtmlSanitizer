using AngleSharp.Css.Dom;
using System;
using System.Collections.Generic;

namespace Ganss.Xss;

/// <summary>
/// Provides options to be used with <see cref="HtmlSanitizer"/>.
/// </summary>
/// <remarks>
/// Every collection here starts out pre-populated from <see cref="HtmlSanitizerDefaults"/>,
/// matching what the parameterless <see cref="HtmlSanitizer()"/> constructor uses, so
/// <c>new HtmlSanitizerOptions()</c> passed to <see cref="HtmlSanitizer(HtmlSanitizerOptions)"/>
/// behaves the same as <see cref="HtmlSanitizer()"/>. Passing a partially-modified instance still
/// replaces the defaults rather than adding to them for any collection you reassign outright - e.g.
/// <c>AllowedTags = new HashSet&lt;string&gt; { "b" }</c> - so mutate the pre-populated collection in
/// place (<c>AllowedTags.Add("video")</c>) when you only want to extend it. If you want a blank
/// slate instead - no tags, attributes, or schemes allowed until you add them - start from
/// <see cref="Empty"/>.
/// </remarks>
public class HtmlSanitizerOptions
{
    /// <summary>
    /// Gets or sets the allowed tag names such as "a" and "div".
    /// </summary>
    public ISet<string> AllowedTags { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.AllowedTags, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed HTML attributes such as "href" and "alt".
    /// </summary>
    public ISet<string> AllowedAttributes { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.AllowedAttributes, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed CSS classes.
    /// </summary>
    public ISet<string> AllowedClasses { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.AllowedClasses, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed CSS properties such as "font" and "margin".
    /// </summary>
    public ISet<string> AllowedCssProperties { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.AllowedCssProperties, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed CSS at-rules such as "@media" and "@font-face".
    /// </summary>
    public ISet<CssRuleType> AllowedAtRules { get; set; } = new HashSet<CssRuleType>(HtmlSanitizerDefaults.AllowedAtRules);

    /// <summary>
    /// Gets or sets the allowed URI schemes such as "http" and "https".
    /// </summary>
    public ISet<string> AllowedSchemes { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.AllowedSchemes, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the HTML attributes that can contain a URI such as "href".
    /// </summary>
    public ISet<string> UriAttributes { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.UriAttributes, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed URI list attributes, whose value is a list of URLs rather than a
    /// single one. See <see cref="HtmlSanitizerDefaults.UriListAttributes"/>.
    /// </summary>
    public ISet<string> UriListAttributes { get; set; } = new HashSet<string>(HtmlSanitizerDefaults.UriListAttributes, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Allow all custom CSS properties (variables) prefixed with <c>--</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// var options = new HtmlSanitizerOptions { AllowCssCustomProperties = true };
    /// </code>
    /// </example>
    public bool AllowCssCustomProperties { get; set; }

    /// <summary>
    /// Allow all HTML5 data attributes; the attributes prefixed with <c>data-</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// var options = new HtmlSanitizerOptions { AllowDataAttributes = true };
    /// </code>
    /// </example>
    public bool AllowDataAttributes { get; set; }

    /// <summary>
    /// Creates a new <see cref="HtmlSanitizerOptions"/> instance whose collections are all empty,
    /// rather than pre-populated from <see cref="HtmlSanitizerDefaults"/> as a plain
    /// <c>new HtmlSanitizerOptions()</c> is. Use this as a starting point when you want to build an
    /// allowlist from scratch instead of narrowing the defaults - most notably leaving
    /// <see cref="UriAttributes"/> empty means URI attributes such as <c>href</c> are not screened
    /// against <see cref="AllowedSchemes"/> at all until you add some.
    /// </summary>
    /// <example>
    /// <code>
    /// var options = HtmlSanitizerOptions.Empty();
    /// options.AllowedTags.Add("b");
    /// var sanitizer = new HtmlSanitizer(options); // allows only &lt;b&gt;, nothing else
    /// </code>
    /// </example>
    public static HtmlSanitizerOptions Empty() => new()
    {
        AllowedTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        AllowedAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        AllowedClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        AllowedCssProperties = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        AllowedAtRules = new HashSet<CssRuleType>(),
        AllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        UriAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        UriListAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
    };
}
