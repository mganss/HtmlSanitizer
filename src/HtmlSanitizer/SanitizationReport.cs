using AngleSharp.Dom;
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
    public class SanitizationReport : ISanitizationReport
    {
        /// <summary>
        /// Gets or sets the list of tags that were removed during sanitation.
        /// </summary>
        public List<string> RemovedTags { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the list of attributes that were removed during sanitation.
        /// </summary>
        public List<string> RemovedAttributes { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the list of attributes that were modified during sanitation.
        /// </summary>
        public List<string> ModifiedAttributes { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the list of CSS classes that were removed during sanitation.
        /// </summary>
        public List<string> RemovedCssClass { get; set; } = new List<string>();

        /// <summary>
        /// Logs a removed attribute for a specific tag.
        /// </summary>
        /// <param name="tag">The tag containing the removed attribute.</param>
        /// <param name="attr">The name of the removed attribute.</param>
        public void LogRemovedAttr(string tag, string attr)
        {
            RemovedAttributes.Add($"{tag} - [{attr}]");
        }

        /// <summary>
        /// Logs a removed tag.
        /// </summary>
        /// <param name="tag">The name of the removed tag.</param>
        public void LogRemovedTag(string tag)
        {
            RemovedTags.Add(tag);
        }

        /// <summary>
        /// Logs a modified attribute for a specific tag.
        /// </summary>
        /// <param name="tag">The tag containing the modified attribute.</param>
        /// <param name="attr">The name of the modified attribute.</param>
        public void LogModifiedAttr(string tag, string attr)
        {
            ModifiedAttributes.Add($"{tag} - [{attr}]");
        }

        /// <summary>
        /// Logs a removed CSS class for a specific tag.
        /// </summary>
        /// <param name="tag">The tag containing the removed CSS class.</param>
        /// <param name="cssclass">The name of the removed CSS class.</param>
        public void LogRemovedCssClass(string tag, string cssclass)
        {
            RemovedCssClass.Add($"{tag} - [{cssclass}]");
        }
    }
}
