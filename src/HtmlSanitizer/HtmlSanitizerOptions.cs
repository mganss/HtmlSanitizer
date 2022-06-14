using System;
using System.Collections.Generic;

namespace Ganss.XSS
{
    public class HtmlSanitizerOptions
    {
        public ICollection<string> AllowedTags { get; set; } = new HashSet<string>();
        public ICollection<string> AllowedAttributes { get; set; } = new HashSet<string>();
        public ICollection<string> AllowedCssProperties { get; set; } = new HashSet<string>();
        public ICollection<string> AllowedAtRules { get; set; } = new HashSet<string>();
        public ICollection<string> AllowedSchemes { get; set; } = new HashSet<string>();
        public ICollection<string> UriAttributes { get; set; } = new HashSet<string>();
    }
}
