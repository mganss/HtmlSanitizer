﻿namespace Ganss.Xss;

/// <summary>
/// Represents an Internationalized Resource Identifier.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="Iri"/> class.
/// </remarks>
/// <param name="value">The value.</param>
/// <param name="scheme">The scheme.</param>
public class Iri(string value, string? scheme = null)
{
    /// <summary>
    /// Gets or sets the value of the IRI.
    /// </summary>
    /// <value>
    /// The value of the IRI.
    /// </value>
    public string Value { get; private set; } = value;

    /// <summary>
    /// Gets a value indicating whether the IRI is absolute.
    /// </summary>
    /// <value>
    ///   <c>true</c> if the IRI is absolute; otherwise, <c>false</c>.
    /// </value>
    public bool IsAbsolute => !string.IsNullOrEmpty(Scheme);

    /// <summary>
    /// Gets or sets the scheme of the IRI, e.g. "https".
    /// </summary>
    /// <value>
    /// The scheme of the IRI.
    /// </value>
    public string? Scheme { get; private set; } = scheme;
}
