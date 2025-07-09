using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ganss.Xss
{
    /// <summary>  
    /// Represents a report of sanitation actions performed on HTML content.  
    /// </summary>  
    public interface ISanitizationReport
    {
        /// <summary>  
        /// Gets or sets the list of tags that were removed during sanitation.  
        /// </summary>  
        List<string> RemovedTags { get; set; }

        /// <summary>  
        /// Gets or sets the list of attributes that were removed during sanitation.  
        /// </summary>  
        List<string> RemovedAttributes { get; set; }

        /// <summary>
        /// Gets or sets the list of CSS classes that were removed during sanitation.
        /// </summary>
        List<string> RemovedCssClass { get; set; }

        /// <summary>  
        /// Gets or sets the list of attributes that were modified during sanitation.  
        /// </summary>  
        List<string> ModifiedAttributes { get; set; }

        /// <summary>  
        /// Logs a tag that was removed during sanitation.  
        /// </summary>  
        /// <param name="tag">The name of the tag that was removed.</param>  
        void LogRemovedTag(string tag);

        /// <summary>  
        /// Logs an attribute that was removed during sanitation.  
        /// </summary>  
        /// <param name="tag">The name of the tag containing the attribute.</param>  
        /// <param name="attr">The name of the attribute that was removed.</param>  
        void LogRemovedAttr(string tag, string attr);

        /// <summary>  
        /// Logs an attribute that was modified during sanitation.  
        /// </summary>  
        /// <param name="tag">The name of the tag containing the attribute.</param>  
        /// <param name="attr">The name of the attribute that was modified.</param>  
        void LogModifiedAttr(string tag, string attr);

        /// <summary>
        /// Logs a CSS class that was removed during sanitation.
        /// </summary>
        /// <param name="tag">The name of the tag containing the CSS class.</param>
        /// <param name="attr">The name of the CSS class that was removed.</param>
        void LogRemovedCssClass(string tag, string cssclass);
    }
}
