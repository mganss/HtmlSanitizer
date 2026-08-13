using AngleSharp.Css.Dom;
using System;
using System.Collections.Generic;

namespace Ganss.Xss;

/// <summary>
/// Provides options to be used with <see cref="HtmlSanitizer"/>.
/// </summary>
/// <remarks>
/// Every collection here starts out <em>empty</em>, unlike the sanitizer produced by the
/// parameterless <see cref="HtmlSanitizer()"/> constructor, which seeds them from
/// <see cref="HtmlSanitizerDefaults"/>. Passing a partially-filled instance to
/// <see cref="HtmlSanitizer(HtmlSanitizerOptions)"/> replaces the defaults instead of adding to
/// them, so anything you leave unset is empty on the resulting sanitizer - most notably
/// <see cref="UriAttributes"/>, whose emptiness means URI attributes such as <c>href</c> are not
/// screened against <see cref="AllowedSchemes"/> at all. If you only want to override a few
/// settings, start from <see cref="CreateDefault"/> instead of <c>new HtmlSanitizerOptions()</c>.
/// </remarks>
public class HtmlSanitizerOptions
{
    /// <summary>
    /// Gets or sets the allowed tag names such as "a" and "div".
    /// </summary>
    public ISet<string> AllowedTags { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed HTML attributes such as "href" and "alt".
    /// </summary>
    public ISet<string> AllowedAttributes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed CSS classes.
    /// </summary>
    public ISet<string> AllowedCssClasses { get; set; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the allowed CSS properties such as "font" and "margin".
    /// </summary>
    public ISet<string> AllowedCssProperties { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed CSS at-rules such as "@media" and "@font-face".
    /// </summary>
    public ISet<CssRuleType> AllowedAtRules { get; set; } = new HashSet<CssRuleType>();

    /// <summary>
    /// Gets or sets the allowed URI schemes such as "http" and "https".
    /// </summary>
    public ISet<string> AllowedSchemes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the HTML attributes that can contain a URI such as "href".
    /// </summary>
    public ISet<string> UriAttributes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the allowed URI list attributes, whose value is a list of URLs rather than a
    /// single one. See <see cref="HtmlSanitizerDefaults.UriListAttributes"/>.
    /// </summary>
    public ISet<string> UriListAttributes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
    /// Creates a new <see cref="HtmlSanitizerOptions"/> instance whose collections are
    /// pre-populated from <see cref="HtmlSanitizerDefaults"/>, matching what the parameterless
    /// <see cref="HtmlSanitizer()"/> constructor uses. Use this as a starting point when you only
    /// want to adjust a handful of settings rather than specifying every collection yourself.
    /// </summary>
    /// <example>
    /// <code>
    /// var options = HtmlSanitizerOptions.CreateDefault();
    /// options.AllowedTags.Add("video");
    /// var sanitizer = new HtmlSanitizer(options);
    /// </code>
    /// </example>
    public static HtmlSanitizerOptions CreateDefault() => new()
    {
        AllowedTags = new HashSet<string>(HtmlSanitizerDefaults.AllowedTags, StringComparer.OrdinalIgnoreCase),
        AllowedAttributes = new HashSet<string>(HtmlSanitizerDefaults.AllowedAttributes, StringComparer.OrdinalIgnoreCase),
        AllowedCssClasses = new HashSet<string>(HtmlSanitizerDefaults.AllowedClasses, StringComparer.OrdinalIgnoreCase),
        AllowedCssProperties = new HashSet<string>(HtmlSanitizerDefaults.AllowedCssProperties, StringComparer.OrdinalIgnoreCase),
        AllowedAtRules = new HashSet<CssRuleType>(HtmlSanitizerDefaults.AllowedAtRules),
        AllowedSchemes = new HashSet<string>(HtmlSanitizerDefaults.AllowedSchemes, StringComparer.OrdinalIgnoreCase),
        UriAttributes = new HashSet<string>(HtmlSanitizerDefaults.UriAttributes, StringComparer.OrdinalIgnoreCase),
        UriListAttributes = new HashSet<string>(HtmlSanitizerDefaults.UriListAttributes, StringComparer.OrdinalIgnoreCase),
    };
}
