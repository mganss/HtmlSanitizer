using AngleSharp.Css.Dom;
using System;
using System.Collections.Generic;

namespace Ganss.XSS
{
    /// <summary>
    /// Provides options to be used with <see cref="HtmlSanitizer"/>.
    /// </summary>
    public class HtmlSanitizerOptions
    {
        /// <summary>
        /// Gets or sets the allowed tag names such as "a" and "div".
        /// </summary>
        public ISet<string> AllowedTags { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Gets or sets the allowed HTML attributes such as "href" and "alt".
        /// </summary>
        public ISet<string> AllowedAttributes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Gets or sets the allowed CSS classes.
        /// </summary>
        public ISet<string> AllowedCssClasses { get; init; } = new HashSet<string>();
        
        /// <summary>
        /// Gets or sets the allowed CSS properties such as "font" and "margin".
        /// </summary>
        public ISet<string> AllowedCssProperties { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Gets or sets the allowed CSS at-rules such as "@media" and "@font-face".
        /// </summary>
        public ISet<CssRuleType> AllowedAtRules { get; init; } = new HashSet<CssRuleType>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Gets or sets the allowed URI schemes such as "http" and "https".
        /// </summary>
        public ISet<string> AllowedSchemes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        /// <summary>
        /// Gets or sets the HTML attributes that can contain a URI such as "href".
        /// </summary>
        public ISet<string> UriAttributes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }
}
