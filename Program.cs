using System;
using System.Linq;
using System.Text;

namespace Html
{
    class Program
    {
        static void Main(string[] args)
        {
            var html = Console.In.ReadToEnd();
            var sanitized = new HtmlSanitizer().Sanitize(html, args.Any() ? args[0] : "");
            Console.OutputEncoding = Encoding.UTF8;
            Console.Out.Write(sanitized);
        }
    }
}
