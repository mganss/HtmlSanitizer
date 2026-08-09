using AngleSharp.Css.Dom;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Ganss.Xss;

/// <summary>
/// Default options.
/// </summary>
public static class HtmlSanitizerDefaults
{
    /// <summary>
    /// The default allowed CSS at-rules.
    /// </summary>
    public static ISet<CssRuleType> AllowedAtRules { get; } = new HashSet<CssRuleType>()
    {
        CssRuleType.Style, CssRuleType.Namespace
    }.ToImmutableHashSet();

    /// <summary>
    /// The default allowed URI schemes.
    /// </summary>
    public static ISet<string> AllowedSchemes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https"
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default allowed HTML tag names.
    /// </summary>
    public static ISet<string> AllowedTags { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
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
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default allowed HTML attributes.
    /// </summary>
    public static ISet<string> AllowedAttributes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
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
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default URI attributes. Values of attributes named here are screened against
    /// <see cref="AllowedSchemes"/>; an attribute carrying a URL that is not listed keeps its
    /// value verbatim, so adding one to <see cref="AllowedAttributes"/> without also adding it
    /// here leaves it unfiltered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Membership is decided by whether a browser resolves the value as a URL and may fetch or
    /// navigate to it. Attributes that merely name something in the current document do not
    /// qualify, and listing one is actively harmful: <c>usemap</c> takes a hash-name reference
    /// (<c>#map</c>), which resolution against a base URL rewrites into an absolute URL that no
    /// longer matches any map, breaking the image map while preventing nothing - a
    /// <c>javascript:</c> value there is inert because nothing ever fetches it. <c>classid</c>
    /// and <c>profile</c> are identifiers in the same way.
    /// </para>
    /// <para>
    /// <c>archive</c>, <c>ping</c> and <c>srcset</c> are absent for a different reason: each
    /// holds a <em>list</em> of URLs, and screening inspects the value as a single URL. Only the
    /// first entry would be examined, so a hostile one in any later position would pass through
    /// untouched - as in <c>srcset="ok.jpg 1x, javascript:alert(1) 2x"</c>. They are screened
    /// entry by entry instead; see <see cref="UriListAttributes"/>.
    /// </para>
    /// <para>
    /// <c>srcdoc</c> is absent for a third reason: it carries a nested HTML document rather than
    /// a URL, so URL screening is the wrong check. Its content is sanitized as HTML instead.
    /// </para>
    /// </remarks>
    public static ISet<string> UriAttributes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "action", "background", "cite", "codebase", "data", "dynsrc", "formaction", "href",
        "icon", "longdesc", "lowsrc", "manifest", "poster", "src", "xlink:href"
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default URI list attributes: attributes whose value is a list of URLs rather than a
    /// single one. Every entry is screened against <see cref="AllowedSchemes"/> individually and
    /// entries that fail are dropped, so a hostile URL cannot hide behind a benign first entry.
    /// </summary>
    /// <remarks>
    /// <c>srcset</c> is a comma-separated list of candidates, each a URL followed by an optional
    /// width or density descriptor. <c>ping</c> and <c>archive</c> are whitespace-separated plain
    /// URL lists.
    /// </remarks>
    public static ISet<string> UriListAttributes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "archive", "ping", "srcset"
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default allowed CSS properties.
    /// </summary>
    public static ISet<string> AllowedCssProperties { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // CSS 3 properties <http://www.w3.org/TR/CSS/#properties>
        "align-content",
        "align-items",
        "align-self",
        "all",
        "animation",
        "animation-delay",
        "animation-direction",
        "animation-duration",
        "animation-fill-mode",
        "animation-iteration-count",
        "animation-name",
        "animation-play-state",
        "animation-timing-function",
        "backface-visibility",
        "background",
        "background-attachment",
        "background-blend-mode",
        "background-clip",
        "background-color",
        "background-image",
        "background-origin",
        "background-position",
        "background-position-x",
        "background-position-y",
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
        "box-decoration-break",
        "box-shadow",
        "box-sizing",
        "break-after",
        "break-before",
        "break-inside",
        "caption-side",
        "caret-color",
        "clear",
        "clip",
        "color",
        "column-count",
        "column-fill",
        "column-gap",
        "column-rule",
        "column-rule-color",
        "column-rule-style",
        "column-rule-width",
        "column-span",
        "column-width",
        "columns",
        "content",
        "counter-increment",
        "counter-reset",
        "cursor",
        "direction",
        "display",
        "empty-cells",
        "filter",
        "flex",
        "flex-basis",
        "flex-direction",
        "flex-flow",
        "flex-grow",
        "flex-shrink",
        "flex-wrap",
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
        "gap",
        "grid",
        "grid-area",
        "grid-auto-columns",
        "grid-auto-flow",
        "grid-auto-rows",
        "grid-column",
        "grid-column-end",
        "grid-column-gap",
        "grid-column-start",
        "grid-gap",
        "grid-row",
        "grid-row-end",
        "grid-row-gap",
        "grid-row-start",
        "grid-template",
        "grid-template-areas",
        "grid-template-columns",
        "grid-template-rows",
        "hanging-punctuation",
        "height",
        "hyphens",
        "image-rendering",
        "isolation",
        "justify-content",
        "left",
        "letter-spacing",
        "line-break",
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
        "mask",
        "mask-clip",
        "mask-composite",
        "mask-image",
        "mask-mode",
        "mask-origin",
        "mask-position",
        "mask-repeat",
        "mask-size",
        "mask-type",
        "max-height",
        "max-width",
        "min-height",
        "min-width",
        "mix-blend-mode",
        "object-fit",
        "object-position",
        "opacity",
        "order",
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
        "perspective",
        "perspective-origin",
        "pointer-events",
        "position",
        "quotes",
        "resize",
        "right",
        "row-gap",
        "scroll-behavior",
        "tab-size",
        "table-layout",
        "text-align",
        "text-align-last",
        "text-combine-upright",
        "text-decoration",
        "text-decoration-color",
        "text-decoration-line",
        "text-decoration-skip",
        "text-decoration-style",
        "text-indent",
        "text-justify",
        "text-orientation",
        "text-overflow",
        "text-shadow",
        "text-transform",
        "text-underline-position",
        "top",
        "transform",
        "transform-origin",
        "transform-style",
        "transition",
        "transition-delay",
        "transition-duration",
        "transition-property",
        "transition-timing-function",
        "unicode-bidi",
        "unicode-range",
        "user-select",
        "vertical-align",
        "visibility",
        "white-space",
        "widows",
        "width",
        "word-break",
        "word-spacing",
        "word-wrap",
        "writing-mode",
        "z-index"
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The default allowed CSS classes.
    /// </summary>
    public static ISet<string> AllowedClasses { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        .ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);
}
