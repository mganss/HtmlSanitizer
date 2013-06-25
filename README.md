HtmlSanitizer
=============

HtmlSanitizer is a class for cleaning HTML fragments from constructs that can lead to [XSS attacks](https://en.wikipedia.org/wiki/Cross-site_scripting).
It uses the excellent C# jQuery port [CsQuery](https://github.com/jamietre/CsQuery) to parse, manipulate, and render HTML and CSS.

In order to facilitate different use cases, HtmlSanitizer can be customized at several levels:
   
- Configure allowed HTML tags through the property `AllowedTags`. All other tags will be stripped.
- Configure allowed HTML attributes through the property `AllowedAttributes`. All other attributes will be stripped.
- Configure allowed CSS property names through the property `AllowedCssProperties`. All other styles will be stripped.
- Configure allowed URI schemes through the property `AllowedCssProperties`. All other URIs will be stripped.
- Configure HTML attributes that contain URIs (such as "src", "href" etc.) through the property `UriAttributes`.
- Provide a base URI that will be used to resolve relative URIs against.

Usage
-----

- Install the CsQuery NuGet package
- Copy `HtmlSanitizer.cs` into your project


    var sanitizer = new HtmlSanitizer();
    var html = @"<script>alert('xss')</script><div onload=""alert('xss')"""
    	+ @"style=""background-color: test"">Test<img src=""test.gif"""
    	+ @"style=""background-image: url(javascript:alert('xss')); margin: 10px""></div>";
    var sanitized = sanitizer.Sanitize(html, "http://www.example.com");
    Assert.That(sanitized, Is.EqualTo(@"<div style=""background-color: test"">"
    	+ @"Test<img style=""margin: 10px"" src=""http://www.example.com/test.gif""></div>");

License
-------

[MIT X11](http://en.wikipedia.org/wiki/MIT_License)
