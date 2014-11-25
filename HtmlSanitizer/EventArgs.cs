using CsQuery;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XSS
{
    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingTag"/> event.
    /// </summary>
    public class RemovingTagEventArgs: CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IDomObject Tag { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingAttribute"/> event.
    /// </summary>
    public class RemovingAttributeEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the attribute to be removed.
        /// </summary>
        /// <value>
        /// The attribute.
        /// </value>
        public KeyValuePair<string, string> Attribute { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingStyle"/> event.
    /// </summary>
    public class RemovingStyleEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the style to be removed.
        /// </summary>
        /// <value>
        /// The style.
        /// </value>
        public KeyValuePair<string, string> Style { get; set; }
    }

}
