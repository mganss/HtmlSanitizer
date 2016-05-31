using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle("HtmlSanitizer")]
[assembly: AssemblyDescription("Cleans HTML from constructs that can be used for cross site scripting (XSS)")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Michael Ganss")]
[assembly: AssemblyProduct("HtmlSanitizer")]
[assembly: AssemblyCopyright("Copyright © 2013-2016 Michael Ganss")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

#if !NETSTANDARD

// Setting ComVisible to false makes the types in this assembly not visible
// to COM components.  If you need to access a type in this assembly from
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("16af04e9-e712-417e-b749-c8d10148dda9")]

#endif

// assembly version information will be reset by AppVeyor
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0.0")]
