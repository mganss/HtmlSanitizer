using AngleSharp;
using AngleSharp.Html;
using AngleSharp.Dom;
using AngleSharp.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ganss.XSS
{
    /// <summary>
    /// HTML5 markup formatter. Identical to <see cref="HtmlMarkupFormatter"/> except for &lt; and &gt; which are
    /// encoded in attribute values.
    /// </summary>
    public class HtmlFormatter: IMarkupFormatter
    {
        /// <summary>
        /// An instance of <see cref="HtmlFormatter"/>.
        /// </summary>
        public static readonly HtmlFormatter Instance = new HtmlFormatter();

        // disable XML comments warnings
        #pragma warning disable 1591

        public virtual string Attribute(IAttr attr)
        {
            var namespaceUri = attr.NamespaceUri;
            var localName = attr.LocalName;
            var value = attr.Value;
            var temp = new StringBuilder();

            if (String.IsNullOrEmpty(namespaceUri))
            {
                temp.Append(localName);
            }
            else if (namespaceUri == NamespaceNames.XmlUri)
            {
                temp.Append(NamespaceNames.XmlPrefix).Append(':').Append(localName);
            }
            else if (namespaceUri == NamespaceNames.XLinkUri)
            {
                temp.Append(NamespaceNames.XLinkPrefix).Append(':').Append(localName);
            }
            else if (namespaceUri == NamespaceNames.XmlNsUri)
            {
                temp.Append(XmlNamespaceLocalName(localName));
            }
            else
            {
                temp.Append(attr.Name);
            }

            temp.Append('=').Append('"');

            for (var i = 0; i < value.Length; i++)
            {
                switch (value[i])
                {
                    case '&': temp.Append("&amp;"); break;
                    case '\u00a0': temp.Append("&nbsp;"); break;
                    case '"': temp.Append("&quot;"); break;
                    case '<': temp.Append("&lt;"); break;
                    case '>': temp.Append("&gt;"); break;
                    default: temp.Append(value[i]); break;
                }
            }

            return temp.Append('"').ToString();
        }

        static string XmlNamespaceLocalName(string name)
        {
            return name != NamespaceNames.XmlNsPrefix ? (NamespaceNames.XmlNsPrefix + ":") : name;
        }

        public virtual string CloseTag(IElement element, bool selfClosing)
        {
            return HtmlMarkupFormatter.Instance.CloseTag(element, selfClosing);
        }

        public virtual string Comment(IComment comment)
        {
            return HtmlMarkupFormatter.Instance.Comment(comment);
        }

        public virtual string Doctype(IDocumentType doctype)
        {
            return HtmlMarkupFormatter.Instance.Doctype(doctype);
        }

        public virtual string OpenTag(IElement element, bool selfClosing)
        {
            var temp = new StringBuilder();

            temp.Append('<');

            if (!string.IsNullOrEmpty(element.Prefix))
            {
                temp.Append(element.Prefix).Append(':');
            }

            temp.Append(element.LocalName);

            foreach (var attribute in element.Attributes)
            {
                temp.Append(' ').Append(Attribute(attribute));
            }

            temp.Append('>');

            return temp.ToString();
        }

        public virtual string Processing(IProcessingInstruction processing)
        {
            return HtmlMarkupFormatter.Instance.Processing(processing);
        }

        public virtual string Text(string text)
        {
            return HtmlMarkupFormatter.Instance.Text(text);
        }

        #pragma warning restore 1591
    }
}
