HtmlSanitizer
=============

[![NuGet version](https://badge.fury.io/nu/HtmlSanitizer.svg)](https://badge.fury.io/nu/HtmlSanitizer)
[![Build status](https://ci.appveyor.com/api/projects/status/418bmfx643iae00c/branch/master?svg=true)](https://ci.appveyor.com/project/mganss/htmlsanitizer/branch/master)
[![codecov.io](https://codecov.io/github/mganss/HtmlSanitizer/coverage.svg?branch=master)](https://codecov.io/github/mganss/HtmlSanitizer?branch=master)
[![Sonarcloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=mganss_HtmlSanitizer&metric=alert_status)](https://sonarcloud.io/dashboard?id=mganss_HtmlSanitizer)

[![netstandard2.0](https://img.shields.io/badge/netstandard-2.0-brightgreen.svg)](https://img.shields.io/badge/netstandard-2.0-brightgreen.svg)
[![net46](https://img.shields.io/badge/net-462-brightgreen.svg)](https://img.shields.io/badge/net-462-brightgreen.svg)
[![net8.0](https://img.shields.io/badge/net-8.0-brightgreen.svg)](https://img.shields.io/badge/net-461-brightgreen.svg)

HtmlSanitizer is a .NET library for cleaning HTML fragments and documents from constructs that can lead to [XSS attacks](https://en.wikipedia.org/wiki/Cross-site_scripting).
It uses [AngleSharp](https://github.com/AngleSharp/AngleSharp) to parse, manipulate, and render HTML and CSS.

Because HtmlSanitizer is based on a robust HTML parser it can also shield you from deliberate or accidental
"tag poisoning" where invalid HTML in one fragment can corrupt the whole document leading to broken layout or style.

In order to facilitate different use cases, HtmlSanitizer can be customized at several levels:
   
- Configure allowed HTML tags through the property `AllowedTags`. All other tags will be stripped.
- Configure allowed HTML attributes through the property `AllowedAttributes`. All other attributes will be stripped.
- Configure allowed CSS property names through the property `AllowedCssProperties`. All other styles will be stripped.
- Configure allowed CSS [at-rules](https://developer.mozilla.org/en-US/docs/Web/CSS/At-rule) through the property `AllowedAtRules`. All other at-rules will be stripped.
- Configure allowed URI schemes through the property `AllowedSchemes`. All other URIs will be stripped.
- Configure HTML attributes that contain URIs (such as "src", "href" etc.) through the property `UriAttributes`.
- Configure HTML attributes that contain a *list* of URIs (such as "srcset", "ping") through the property `UriListAttributes`. Every entry is checked separately.
- Provide a base URI that will be used to resolve relative URIs against.
- Sanitize a fragment for the element it will be inserted into, rather than for `<body>`, through `SanitizeFragment()`. This keeps markup such as a lone `<th>` that is only valid deeper in the tree.
- Cancelable events are raised before a tag, attribute, or style is removed.
- All of the above can be set in one go by passing an `HtmlSanitizerOptions` object to the constructor. Note that `new HtmlSanitizerOptions()` starts with *empty* collections rather than the defaults - use `HtmlSanitizerOptions.CreateDefault()` if you only want to override a few settings, see [Configuring with `HtmlSanitizerOptions`](#configuring-with-htmlsanitizeroptions).

Usage
-----

Install the [HtmlSanitizer NuGet package](https://www.nuget.org/packages/HtmlSanitizer/). Then:

```C#
using Ganss.Xss;
var sanitizer = new HtmlSanitizer();
var html = @"<script>alert('xss')</script><div onload=""alert('xss')"""
    + @"style=""background-color: rgba(0, 0, 0, 1)"">Test<img src=""test.png"""
    + @"style=""background-image: url(javascript:alert('xss')); margin: 10px""></div>";
var sanitized = sanitizer.Sanitize(html, "https://www.example.com");
var expected = @"<div style=""background-color: rgba(0, 0, 0, 1)"">"
    + @"Test<img src=""https://www.example.com/test.png"" style=""margin: 10px""></div>";
Assert.Equal(expected, sanitized);
```

There's an [online demo](https://xss.ganss.org/), plus there's also a [.NET Fiddle](https://dotnetfiddle.net/892nOk) you can play with.

More example code and a description of possible options can be found in the [Wiki](https://github.com/mganss/HtmlSanitizer/wiki).

### Configuring with `HtmlSanitizerOptions`

A sanitizer can also be configured in one go by passing an `HtmlSanitizerOptions` object to the constructor:

```C#
var sanitizer = new HtmlSanitizer(new HtmlSanitizerOptions
{
    AllowedTags = new HashSet<string> { "a", "img" },
    AllowedAttributes = new HashSet<string> { "href", "src" },
    UriAttributes = HtmlSanitizerDefaults.UriAttributes,
    AllowedSchemes = HtmlSanitizerDefaults.AllowedSchemes,
});
```

**Every collection on `HtmlSanitizerOptions` starts out empty, so this constructor replaces the defaults instead of adding to them.** Whatever you leave unset is empty on the resulting sanitizer - unlike the parameterless `new HtmlSanitizer()`, which seeds all of these from `HtmlSanitizerDefaults`. Set each collection you care about explicitly, using the corresponding `HtmlSanitizerDefaults` member where you want the default value, or start from `HtmlSanitizerOptions.CreateDefault()` as shown below.

This matters most for `UriAttributes`, which is a *screening* list rather than an allow list: leaving it empty does not deny URI attributes, it means no attribute is treated as carrying a URI at all. Its value is then never checked against `AllowedSchemes`, so

```C#
// UriAttributes not set - href is not screened
var sanitizer = new HtmlSanitizer(new HtmlSanitizerOptions
{
    AllowedTags = new HashSet<string> { "a" },
    AllowedAttributes = new HashSet<string> { "href" },
});
// <a href="javascript:alert(1)">click</a> is preserved as-is
```

`UriAttributes` and `AllowedSchemes` need to be set together. Screening an attribute against an empty scheme set drops every absolute URI, valid `https` ones included:

```C#
// UriAttributes set but AllowedSchemes left empty - every absolute URI is dropped
var sanitizer = new HtmlSanitizer(new HtmlSanitizerOptions
{
    AllowedTags = new HashSet<string> { "a" },
    AllowedAttributes = new HashSet<string> { "href" },
    UriAttributes = HtmlSanitizerDefaults.UriAttributes,
});
// <a href="https://example.com">ok</a> becomes <a>ok</a>
```

If you only want to adjust a handful of settings, it is safer to start from the defaults and modify the properties, because everything you do not touch keeps its default value. You can do this either on the sanitizer itself:

```C#
var sanitizer = new HtmlSanitizer();
sanitizer.AllowedTags.Clear();
sanitizer.AllowedTags.Add("a");
sanitizer.AllowedTags.Add("img");
// UriAttributes, AllowedSchemes, etc. remain at their defaults
```

or, if you want an `HtmlSanitizerOptions` instance (e.g. to build it up before constructing the sanitizer), by starting from `HtmlSanitizerOptions.CreateDefault()` instead of `new HtmlSanitizerOptions()`:

```C#
var options = HtmlSanitizerOptions.CreateDefault();
options.AllowedTags.Clear();
options.AllowedTags.Add("a");
options.AllowedTags.Add("img");
// UriAttributes, AllowedSchemes, etc. remain at their defaults
var sanitizer = new HtmlSanitizer(options);
```

### Tags allowed by default
`a`,
`abbr`,
`acronym`,
`address`,
`area`,
`article`,
`aside`,
`b`,
`bdi`,
`big`,
`blockquote`,
`body`,
`br`,
`button`,
`caption`,
`center`,
`cite`,
`code`,
`col`,
`colgroup`,
`data`,
`datalist`,
`dd`,
`del`,
`details`,
`dfn`,
`dir`,
`div`,
`dl`,
`dt`,
`em`,
`fieldset`,
`figcaption`,
`figure`,
`font`,
`footer`,
`form`,
`h1`,
`h2`,
`h3`,
`h4`,
`h5`,
`h6`,
`head`,
`header`,
`hr`,
`html`,
`i`,
`img`,
`input`,
`ins`,
`kbd`,
`keygen`,
`label`,
`legend`,
`li`,
`main`,
`map`,
`mark`,
`menu`,
`menuitem`,
`meter`,
`nav`,
`ol`,
`optgroup`,
`option`,
`output`,
`p`,
`pre`,
`progress`,
`q`,
`rp`,
`rt`,
`ruby`,
`s`,
`samp`,
`section`,
`select`,
`small`,
`span`,
`strike`,
`strong`,
`sub`,
`summary`,
`sup`,
`table`,
`tbody`,
`td`,
`textarea`,
`tfoot`,
`th`,
`thead`,
`time`,
`tr`,
`tt`,
`u`,
`ul`,
`var`,
`wbr`

### Attributes allowed by default
`abbr`,
`accept-charset`,
`accept`,
`accesskey`,
`action`,
`align`,
`alt`,
`autocomplete`,
`autosave`,
`axis`,
`bgcolor`,
`border`,
`cellpadding`,
`cellspacing`,
`challenge`,
`char`,
`charoff`,
`charset`,
`checked`,
`cite`,
`clear`,
`color`,
`cols`,
`colspan`,
`compact`,
`contenteditable`,
`coords`,
`datetime`,
`dir`,
`disabled`,
`draggable`,
`dropzone`,
`enctype`,
`for`,
`frame`,
`headers`,
`height`,
`high`,
`href`,
`hreflang`,
`hspace`,
`ismap`,
`keytype`,
`label`,
`lang`,
`list`,
`longdesc`,
`low`,
`max`,
`maxlength`,
`media`,
`method`,
`min`,
`multiple`,
`name`,
`nohref`,
`noshade`,
`novalidate`,
`nowrap`,
`open`,
`optimum`,
`pattern`,
`placeholder`,
`prompt`,
`pubdate`,
`radiogroup`,
`readonly`,
`rel`,
`required`,
`rev`,
`reversed`,
`rows`,
`rowspan`,
`rules`,
`scope`,
`selected`,
`shape`,
`size`,
`span`,
`spellcheck`,
`src`,
`start`,
`step`,
`style`,
`summary`,
`tabindex`,
`target`,
`title`,
`type`,
`usemap`,
`valign`,
`value`,
`vspace`,
`width`,
`wrap`

_Note:_ to prevent [classjacking](https://html5sec.org/#123) and interference with classes where the sanitized fragment is to be integrated, the `class` attribute is disallowed by default. 
It can be added as follows:
```C#
var sanitizer = new HtmlSanitizer();
sanitizer.AllowedAttributes.Add("class");
var sanitized = sanitizer.Sanitize(html);
```

### CSS properties allowed by default
`align-content`,
`align-items`,
`align-self`,
`all`,
`animation`,
`animation-delay`,
`animation-direction`,
`animation-duration`,
`animation-fill-mode`,
`animation-iteration-count`,
`animation-name`,
`animation-play-state`,
`animation-timing-function`,
`backface-visibility`,
`background`,
`background-attachment`,
`background-blend-mode`,
`background-clip`,
`background-color`,
`background-image`,
`background-origin`,
`background-position`,
`background-position-x`,
`background-position-y`,
`background-repeat`,
`background-repeat-x`,
`background-repeat-y`,
`background-size`,
`border`,
`border-bottom`,
`border-bottom-color`,
`border-bottom-left-radius`,
`border-bottom-right-radius`,
`border-bottom-style`,
`border-bottom-width`,
`border-collapse`,
`border-color`,
`border-image`,
`border-image-outset`,
`border-image-repeat`,
`border-image-slice`,
`border-image-source`,
`border-image-width`,
`border-left`,
`border-left-color`,
`border-left-style`,
`border-left-width`,
`border-radius`,
`border-right`,
`border-right-color`,
`border-right-style`,
`border-right-width`,
`border-spacing`,
`border-style`,
`border-top`,
`border-top-color`,
`border-top-left-radius`,
`border-top-right-radius`,
`border-top-style`,
`border-top-width`,
`border-width`,
`bottom`,
`box-decoration-break`,
`box-shadow`,
`box-sizing`,
`break-after`,
`break-before`,
`break-inside`,
`caption-side`,
`caret-color`,
`clear`,
`clip`,
`color`,
`column-count`,
`column-fill`,
`column-gap`,
`column-rule`,
`column-rule-color`,
`column-rule-style`,
`column-rule-width`,
`column-span`,
`column-width`,
`columns`,
`content`,
`counter-increment`,
`counter-reset`,
`cursor`,
`direction`,
`display`,
`empty-cells`,
`filter`,
`flex`,
`flex-basis`,
`flex-direction`,
`flex-flow`,
`flex-grow`,
`flex-shrink`,
`flex-wrap`,
`float`,
`font`,
`font-family`,
`font-feature-settings`,
`font-kerning`,
`font-language-override`,
`font-size`,
`font-size-adjust`,
`font-stretch`,
`font-style`,
`font-synthesis`,
`font-variant`,
`font-variant-alternates`,
`font-variant-caps`,
`font-variant-east-asian`,
`font-variant-ligatures`,
`font-variant-numeric`,
`font-variant-position`,
`font-weight`,
`gap`,
`grid`,
`grid-area`,
`grid-auto-columns`,
`grid-auto-flow`,
`grid-auto-rows`,
`grid-column`,
`grid-column-end`,
`grid-column-gap`,
`grid-column-start`,
`grid-gap`,
`grid-row`,
`grid-row-end`,
`grid-row-gap`,
`grid-row-start`,
`grid-template`,
`grid-template-areas`,
`grid-template-columns`,
`grid-template-rows`,
`hanging-punctuation`,
`height`,
`hyphens`,
`image-rendering`,
`isolation`,
`justify-content`,
`left`,
`letter-spacing`,
`line-break`,
`line-height`,
`list-style`,
`list-style-image`,
`list-style-position`,
`list-style-type`,
`margin`,
`margin-bottom`,
`margin-left`,
`margin-right`,
`margin-top`,
`mask`,
`mask-clip`,
`mask-composite`,
`mask-image`,
`mask-mode`,
`mask-origin`,
`mask-position`,
`mask-repeat`,
`mask-size`,
`mask-type`,
`max-height`,
`max-width`,
`min-height`,
`min-width`,
`mix-blend-mode`,
`object-fit`,
`object-position`,
`opacity`,
`order`,
`orphans`,
`outline`,
`outline-color`,
`outline-offset`,
`outline-style`,
`outline-width`,
`overflow`,
`overflow-wrap`,
`overflow-x`,
`overflow-y`,
`padding`,
`padding-bottom`,
`padding-left`,
`padding-right`,
`padding-top`,
`page-break-after`,
`page-break-before`,
`page-break-inside`,
`perspective`,
`perspective-origin`,
`pointer-events`,
`position`,
`quotes`,
`resize`,
`right`,
`row-gap`,
`scroll-behavior`,
`tab-size`,
`table-layout`,
`text-align`,
`text-align-last`,
`text-combine-upright`,
`text-decoration`,
`text-decoration-color`,
`text-decoration-line`,
`text-decoration-skip`,
`text-decoration-style`,
`text-indent`,
`text-justify`,
`text-orientation`,
`text-overflow`,
`text-shadow`,
`text-transform`,
`text-underline-position`,
`top`,
`transform`,
`transform-origin`,
`transform-style`,
`transition`,
`transition-delay`,
`transition-duration`,
`transition-property`,
`transition-timing-function`,
`unicode-bidi`,
`unicode-range`,
`user-select`,
`vertical-align`,
`visibility`,
`white-space`,
`widows`,
`width`,
`word-break`,
`word-spacing`,
`word-wrap`,
`writing-mode`,
`z-index`

### CSS at-rules allowed by default
`namespace`, `style`

`style` refers to style declarations within other at-rules such as `@media`. Disallowing `@namespace` while allowing other types of at-rules can lead to errors.
Property declarations in `@font-face` and `@viewport` are not sanitized.

_Note:_ the `style` tag is disallowed by default.

### URI schemes allowed by default
`http`, `https`

_Note:_ [Protocol-relative URLs](https://en.wikipedia.org/wiki/Wikipedia:Protocol-relative_URL)  (e.g. <a href="//github.com">//github.com</a>) are allowed by default (as are other relative URLs).

to allow `mailto:` links: 

```C#
sanitizer.AllowedSchemes.Add("mailto");
```

### Default attributes that contain URIs
`action`, `background`, `cite`, `codebase`, `data`, `dynsrc`, `formaction`, `href`, `icon`, `longdesc`, `lowsrc`, `manifest`, `poster`, `src`, `xlink:href`

The value of an attribute listed in `UriAttributes` is checked against `AllowedSchemes`. An attribute that carries a URI but is *not* listed keeps its value as-is, so if you add such an attribute to `AllowedAttributes` you should add it to `UriAttributes` as well:

```C#
sanitizer.AllowedAttributes.Add("data-thumbnail");
sanitizer.UriAttributes.Add("data-thumbnail");
```

The same applies to the attributes listed above when you configure the sanitizer through `HtmlSanitizerOptions`, whose `UriAttributes` starts out empty - see [Configuring with `HtmlSanitizerOptions`](#configuring-with-htmlsanitizeroptions).

_Note:_ attributes that merely name something in the same document rather than locating a resource - `usemap`, `classid`, `profile` - are deliberately not treated as URI attributes. Nothing fetches them, and resolving them against a base URI would break them: `usemap="#map"` has to stay a hash-name reference to match its `<map>`.

### Default attributes that contain lists of URIs
`archive`, `ping`, `srcset`

These hold several URIs in one value, so each entry is checked on its own and the failing ones are dropped; the attribute itself is removed only if nothing survives. `srcset` is parsed as a candidate list so that descriptors are kept with the URI they belong to, and commas inside a URI do not split it.

```C#
// srcset="https://example.com/a.jpg 1x, javascript:alert(1) 2x"
// becomes srcset="https://example.com/a.jpg 1x"
```

Checking such an attribute through `UriAttributes` instead would inspect the whole value as a single URI, which only ever looks at the first entry - so use `UriListAttributes` for these.

### The `srcdoc` attribute

`srcdoc` holds a complete HTML document rather than a URI, and a browser parses and runs it in its own browsing context. It is therefore not a URI attribute: if you allow it, its content is sanitized as HTML with the same settings as the surrounding document.

```C#
sanitizer.AllowedTags.Add("iframe");
sanitizer.AllowedAttributes.Add("srcdoc");
// <iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;"></iframe>
// becomes <iframe srcdoc="&lt;img src=&quot;x&quot;&gt;"></iframe>
```

Nested `srcdoc` documents are sanitized as well, up to a fixed depth, beyond which the attribute is removed.

### Sanitizing a fragment in context

`Sanitize()` parses its input as if it were being inserted into `<body>`. Markup that is only valid deeper in the tree is therefore discarded by the parser before sanitization ever sees it, exactly as it would be by `div.innerHTML` in a browser:

```C#
sanitizer.Sanitize(@"<th>Header</th>"); // "Header" - the th is gone
```

Use `SanitizeFragment()` to name the element the fragment will be inserted into:

```C#
sanitizer.SanitizeFragment(@"<th>Header</th>", "tr"); // "<th>Header</th>"
```

This is useful when you sanitize table rows, list items, or `<option>` elements on their own, e.g. to return them from an endpoint that patches part of a page.

The result is only safe in the context it was sanitized for, so insert it into that same context. A fragment sanitized for `tr` that is put into a `<div>` instead gets re-parsed under different rules, and the tree the browser ends up with is not the one that was screened.

Contexts whose content is raw text - `style`, `script`, `xmp`, `iframe`, `noembed` and `noframes` - are rejected with an `ArgumentException`. The parser turns a fragment in those into a single text node, so there are no tags or attributes left to remove and nothing is escaped on the way out; the input would come back verbatim, looking sanitized without having been. An unknown context name is rejected too, so a typo fails instead of quietly falling back to `<body>` behaviour.

There is also an overload taking an `IElement`, for contexts outside the HTML namespace that a tag name alone cannot express:

```C#
sanitizer.AllowedTags.Add("text");
using var document = sanitizer.HtmlParserFactory().ParseDocument(string.Empty);
var context = document.CreateElement(NamespaceNames.SvgUri, "svg");
sanitizer.SanitizeFragment(@"<text>hi</text>", context); // "<text>hi</text>"
```

The element only selects the parser's insertion mode and is left untouched, so you can reuse one across calls.

### Thread safety

The `Sanitize()`, `SanitizeFragment()` and `SanitizeDocument()` methods are thread-safe, i.e. you can use these methods on a single shared instance from different threads provided you do not simultaneously set instance or static properties. A typical use case is that you prepare an `HtmlSanitizer` instance once (i.e. set desired properties such as `AllowedTags` etc.) from a single thread, then call `Sanitize()`/`SanitizeFragment()`/`SanitizeDocument()` from multiple threads.

### Text content not necessarily preserved as-is

Please note that as the input is parsed by AngleSharp's HTML parser and then rendered back out, you cannot expect the text content to be preserved exactly as it was input, even if no elements or attributes were removed. Examples:

- `4 < 5` becomes `4 &lt; 5`
- `<SPAN>test</p>` becomes `<span>test<p></p></span>`
- `<span title='test'>test</span>` becomes `<span title="test">test</span>`

On the other hand, although some broken HTML is fixed by the parser, the output might still contain invalid HTML. Examples:

- `<div><li>test</li></div>`
- `<ul><br><li>test</li></ul>`
- `<h3><p>test</p></h3>`

License
-------

[MIT License](https://en.wikipedia.org/wiki/MIT_License)
