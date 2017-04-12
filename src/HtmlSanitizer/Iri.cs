using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Ganss.XSS
{
    public class Iri
    {
        public string Value { get; set; }
        public bool IsAbsolute => !string.IsNullOrEmpty(Scheme);
        public string Scheme { get; set; }
    }
}
