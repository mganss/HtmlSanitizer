using AngleSharp.Dom;
using AngleSharp.Dom.Css;
using AngleSharp.Dom.Html;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Ganss.XSS
{
    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.PostProcessDom"/> event.
    /// </summary>
    public class PostProcessDomEventArgs : EventArgs
    {
        /// <summary>
        /// Gets or sets the document.
        /// </summary>
        /// <value>
        /// The document.
        /// </value>
        public IHtmlDocument Document { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PostProcessDomEventArgs"/> class.
        /// </summary>
        public PostProcessDomEventArgs()
        { }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.PostProcessNode"/> event.
    /// </summary>
    public class PostProcessNodeEventArgs : EventArgs
    {
        /// <summary>
        /// Gets or sets the document.
        /// </summary>
        /// <value>
        /// The document.
        /// </value>
        public IHtmlDocument Document { get; set; }

        /// <summary>
        /// Gets or sets the DOM node to be processed.
        /// </summary>
        /// <value>
        /// The DOM node.
        /// </value>
        public INode Node { get; set; }

        /// <summary>
        /// Gets the replacement nodes. Leave empty if no replacement should occur.
        /// </summary>
        /// <value>
        /// The replacement nodes.
        /// </value>
        public IList<INode> ReplacementNodes { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PostProcessNodeEventArgs"/> class.
        /// </summary>
        public PostProcessNodeEventArgs()
        {
            ReplacementNodes = new List<INode>();
        }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingTag"/> event.
    /// </summary>
    public class RemovingTagEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IElement Tag { get; set; }

        /// <summary>
        /// Gets or sets the reason why the tag will be removed
        /// </summary>
        /// <value>
        /// The reason.
        /// </value>
        public RemoveReason Reason { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingAttribute"/> event.
    /// </summary>
    public class RemovingAttributeEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag containing the attribute to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IElement Tag { get; set; }

        /// <summary>
        /// Gets or sets the attribute to be removed.
        /// </summary>
        /// <value>
        /// The attribute.
        /// </value>
        public IAttr Attribute { get; set; }

        /// <summary>
        /// Gets or sets the reason why the attribute will be removed
        /// </summary>
        /// <value>
        /// The reason.
        /// </value>
        public RemoveReason Reason { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingStyle"/> event.
    /// </summary>
    public class RemovingStyleEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag containing the style to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IElement Tag { get; set; }

        /// <summary>
        /// Gets or sets the style to be removed.
        /// </summary>
        /// <value>
        /// The style.
        /// </value>
        public ICssProperty Style { get; set; }

        /// <summary>
        /// Gets or sets the reason why the style will be removed
        /// </summary>
        /// <value>
        /// The reason.
        /// </value>
        public RemoveReason Reason { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingAtRule"/> event.
    /// </summary>
    public class RemovingAtRuleEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag containing the at-rule to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IElement Tag { get; set; }

        /// <summary>
        /// Gets or sets the rule to be removed.
        /// </summary>
        /// <value>
        /// The rule.
        /// </value>
        public ICssRule Rule { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingComment"/> event.
    /// </summary>
    public class RemovingCommentEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the comment node to be removed.
        /// </summary>
        /// <value>
        /// The comment node.
        /// </value>
        public IComment Comment { get; set; }
    }

    /// <summary>
    /// Provides data for the <see cref="HtmlSanitizer.RemovingCssClass"/> event.
    /// </summary>
    public class RemovingCssClassEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the tag containing the CSS class to be removed.
        /// </summary>
        /// <value>
        /// The tag.
        /// </value>
        public IElement Tag { get; set; }

        /// <summary>
        /// Gets or sets the CSS class to be removed.
        /// </summary>
        /// <value>
        /// The CSS class.
        /// </value>
        public string CssClass { get; set; }

        /// <summary>
        /// Gets or sets the reason why the CSS class will be removed.
        /// </summary>
        /// <value>
        /// The reason.
        /// </value>
        public RemoveReason Reason { get; set; }
    }
}
