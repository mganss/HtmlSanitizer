using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ganss.Xss
{
    /// <summary>
    /// Provides functionality to generate a log for a sanitization report.
    /// </summary>
    public static class SanitizationReportLogger
    {
        /// <summary>
        /// Generates a detailed log based on the provided sanitization report.
        /// </summary>
        /// <param name="report">The sanitization report containing details of removed or modified elements.</param>
        /// <returns>A string representation of the sanitization report log.</returns>
        public static string GenerateLog(ISanitizationReport report)
        {
            var sb = new StringBuilder();

            sb.AppendLine("Sanitization Report");
            sb.AppendLine(new string('-', 40));

            // Removed Tags
            if (report.RemovedTags.Any())
            {
                sb.AppendLine("Removed Tags:");
                foreach (var tag in report.RemovedTags.Distinct())
                    sb.AppendLine($"  - <{tag}>");
            }
            else
            {
                sb.AppendLine("No tags were removed.");
            }

            sb.AppendLine();

            // Removed Attributes
            if (report.RemovedAttributes.Any())
            {
                sb.AppendLine("Removed Attributes:");
                foreach (var attr in report.RemovedAttributes.Distinct())
                    sb.AppendLine($"  - {attr}");
            }
            else
            {
                sb.AppendLine("No attributes were removed.");
            }

            sb.AppendLine();

            // Removed Css Class
            if (report.RemovedCssClass.Any())
            {
                sb.AppendLine("Removed CSS Class:");
                foreach (var attr in report.RemovedCssClass.Distinct())
                    sb.AppendLine($"  - {attr}");
            }
            else
            {
                sb.AppendLine("No css class were removed.");
            }

            sb.AppendLine();
            // Modified Attributes
            if (report.ModifiedAttributes.Any())
            {
                sb.AppendLine("Modified Attributes:");
                foreach (var attr in report.ModifiedAttributes.Distinct())
                    sb.AppendLine($"  - {attr}");
            }
            else
            {
                sb.AppendLine("No attributes were modified.");
            }

            sb.AppendLine(new string('-', 40));

            return sb.ToString();
        }
    }

}
