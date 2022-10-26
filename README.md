HtmlSanitizer
=============

[![NuGet version](https://badge.fury.io/nu/HtmlSanitizer.svg)](https://badge.fury.io/nu/HtmlSanitizer)
[![Build status](https://ci.appveyor.com/api/projects/status/418bmfx643iae00c/branch/master?svg=true)](https://ci.appveyor.com/project/mganss/htmlsanitizer/branch/master)
[![codecov.io](https://codecov.io/github/mganss/HtmlSanitizer/coverage.svg?branch=master)](https://codecov.io/github/mganss/HtmlSanitizer?branch=master)
[![Sonarcloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=mganss_HtmlSanitizer&metric=alert_status)](https://sonarcloud.io/dashboard?id=mganss_HtmlSanitizer)

[![netstandard2.0](https://img.shields.io/badge/netstandard-2.0-brightgreen.svg)](https://img.shields.io/badge/netstandard-2.0-brightgreen.svg)
[![net46](https://img.shields.io/badge/net-461-brightgreen.svg)](https://img.shields.io/badge/net-461-brightgreen.svg)

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
- Provide a base URI that will be used to resolve relative URIs against.
- Cancelable events are raised before a tag, attribute, or style is removed.

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
`body`
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
`action`, `background`, `dynsrc`, `href`, `lowsrc`, `src`

### Thread safety

The `Sanitize()` and `SanitizeDocument()` methods are thread-safe, i.e. you can use these methods on a single shared instance from different threads provided you do not simultaneously set instance or static properties. A typical use case is that you prepare an `HtmlSanitizer` instance once (i.e. set desired properties such as `AllowedTags` etc.) from a single thread, then call `Sanitize()`/`SanitizeDocument()` from multiple threads.

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
