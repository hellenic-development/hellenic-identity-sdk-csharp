using System.Text.Json.Serialization;

namespace Hellenic.Identity.SDK.Models;

/// <summary>
/// Client kinds accepted by POST /clients (mirrors Go identity.ClientKind).
/// The wire value is a plain string.
/// </summary>
public static class ClientKind
{
    /// <summary>A server application: password and refresh token grants, user management scopes and an encrypted token.</summary>
    public const string Server = "server";

    /// <summary>A user application: authorization code flow (and device code with a verification URI) and a plain token.</summary>
    public const string User = "user";

    /// <summary>A server application that may also manage clients.</summary>
    public const string Admin = "admin";
}

/// <summary>
/// OAuth2 client application (mirrors Go oauth2.Client)
/// </summary>
public class OAuth2Client
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("created_at")]
    public DateTime? CreatedAt { get; set; }

    [JsonPropertyName("updated_at")]
    public DateTime? UpdatedAt { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("website")]
    public string Website { get; set; } = string.Empty;

    [JsonPropertyName("logo_url")]
    public string LogoURL { get; set; } = string.Empty;

    [JsonPropertyName("redirect_uri")]
    public string RedirectURI { get; set; } = string.Empty;

    [JsonPropertyName("verification_uri")]
    public string VerificationURI { get; set; } = string.Empty;

    [JsonPropertyName("secret")]
    public string? Secret { get; set; } // Blank or absent in list responses

    [JsonPropertyName("grant_types")]
    public List<string> GrantTypes { get; set; } = new();

    [JsonPropertyName("scopes")]
    public List<string> Scopes { get; set; } = new();

    [JsonPropertyName("code_max_age")]
    public int CodeMaxAge { get; set; } // Seconds

    [JsonPropertyName("access_max_age")]
    public int AccessMaxAge { get; set; } // Seconds

    [JsonPropertyName("refresh_max_age")]
    public int RefreshMaxAge { get; set; } // Seconds

    [JsonPropertyName("version")]
    public int Version { get; set; } // Incremented when the client tokens are revoked
}

/// <summary>
/// Create client request, the body of POST /clients (mirrors Go identity.CreateClientRequest)
/// </summary>
public class CreateClientRequest
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("website")]
    public string Website { get; set; } = string.Empty;

    [JsonPropertyName("logo_url")]
    public string LogoURL { get; set; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty; // One of the ClientKind constants

    [JsonPropertyName("redirect_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RedirectURI { get; set; } // Required for the user kind

    [JsonPropertyName("verification_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? VerificationURI { get; set; } // Adds the device code grant to a user client

    [JsonPropertyName("code_max_age")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? CodeMaxAge { get; set; } // Seconds, null means the default of the kind

    [JsonPropertyName("access_max_age")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? AccessMaxAge { get; set; } // Seconds, null means the default of the kind

    [JsonPropertyName("refresh_max_age")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RefreshMaxAge { get; set; } // Seconds, null means the default of the kind
}

/// <summary>
/// Client credentials (mirrors Go identity.ClientCredentials).
/// Audience is the client ID, consumers put it in their accepted audiences.
/// </summary>
public class ClientCredentials
{
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty; // One of the ClientKind constants

    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("encryption_key")]
    public string? EncryptionKey { get; set; } // Server and admin clients only, absent for the user kind
}

/// <summary>
/// Create client response (mirrors Go identity.CreateClientResponse).
/// The Go type embeds the credentials, so the JSON is flat next to the client.
/// </summary>
public class CreateClientResponse : ClientCredentials
{
    [JsonPropertyName("client")]
    public OAuth2Client Client { get; set; } = new(); // Secret included
}

/// <summary>
/// Client filter for listing clients (mirrors Go oauth2.ClientFilter)
/// </summary>
public class ClientFilter
{
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }

    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; set; }

    [JsonPropertyName("sort")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sort { get; set; } // "name", "created_at" or "updated_at"

    [JsonPropertyName("sort_descending")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool SortDescending { get; set; }
}

/// <summary>
/// Count clients response, the body of GET /clients/count (mirrors Go identity.CountClientsResponse)
/// </summary>
public class CountClientsResponse
{
    [JsonPropertyName("total_count")]
    public long TotalCount { get; set; }
}
