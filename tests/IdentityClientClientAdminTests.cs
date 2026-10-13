using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;

namespace Hellenic.Identity.SDK.Tests;

/// <summary>
/// Tests for the client management methods (the /clients admin routes).
/// Each test asserts the outgoing request through the WireMock log.
/// </summary>
public class IdentityClientClientAdminTests : IDisposable
{
    private const string ClientToken = "test-admin-client-token";
    private const string ClientId = "0b6f3c1e-1d2a-4c7e-9f00-123456789abc";

    private readonly WireMockServer _mockServer;
    private readonly RecordingHandler _recorder;
    private readonly HttpClient _httpClient;
    private readonly IOptions<AppConfiguration> _config;

    public IdentityClientClientAdminTests()
    {
        _mockServer = WireMockServer.Start();

        _config = Options.Create(new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = ClientToken,
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "medium"
            }
        });

        // WireMock logs decoded paths, the recorder keeps the URIs as they went on the wire.
        _recorder = new RecordingHandler { InnerHandler = new HttpClientHandler() };
        _httpClient = new HttpClient(_recorder);
        _httpClient.BaseAddress = new Uri(_mockServer.Urls[0]);

        SetupJwksMock();
    }

    private sealed class RecordingHandler : DelegatingHandler
    {
        public List<Uri> RequestUris { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri!);
            return base.SendAsync(request, cancellationToken);
        }
    }

    public void Dispose()
    {
        _mockServer.Dispose();
        _httpClient.Dispose();
    }

    private void SetupJwksMock()
    {
        var jwkSet = new
        {
            keys = new[]
            {
                new
                {
                    kty = "OKP",
                    crv = "Ed25519",
                    x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                    kid = "ed25519-key-1",
                    alg = "EdDSA",
                    use = "sig"
                }
            }
        };

        _mockServer
            .Given(Request.Create().WithPath("/.well-known/jwks.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(jwkSet));
    }

    private async Task<IdentityClient<TestUserModel>> CreateClientAsync()
    {
        var logger = new Mock<ILogger<IdentityClient<TestUserModel>>>();
        var client = new IdentityClient<TestUserModel>(_config, logger.Object, _httpClient);
        Assert.True(await client.InitializeAsync());
        return client;
    }

    private static IResponseBuilder JsonResponse(int status, string body)
    {
        return Response.Create()
            .WithStatusCode(status)
            .WithHeader("Content-Type", "application/json")
            .WithBody(body);
    }

    // The single request sent to a /clients route.
    private IRequestMessage ClientsRequest()
    {
        return _mockServer.LogEntries
            .Select(e => e.RequestMessage)
            .Single(r => r.Path.StartsWith("/clients"));
    }

    private static void AssertToken(IRequestMessage request)
    {
        var header = request.Headers!
            .Single(h => string.Equals(h.Key, "X-Token", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(ClientToken, Assert.Single(header.Value));
    }

    private static string ClientJson(string secret)
    {
        var secretField = secret.Length > 0 ? $"\"secret\": \"{secret}\"," : string.Empty;
        return $$"""
            {
                "id": "{{ClientId}}",
                "created_at": "2026-10-13T17:50:37",
                "updated_at": "2026-10-13T18:01:02",
                "name": "billing-service",
                "website": "https://billing.example.com",
                "logo_url": "https://billing.example.com/logo.png",
                "redirect_uri": "",
                "verification_uri": "",
                {{secretField}}
                "grant_types": ["client_credentials"],
                "scopes": ["user:read"],
                "code_max_age": 3600,
                "access_max_age": 3600,
                "refresh_max_age": 604800,
                "version": 2
            }
            """;
    }

    private static CreateClientRequest ServerClientRequest() => new()
    {
        Name = "billing-service",
        Website = "https://billing.example.com",
        LogoURL = "https://billing.example.com/logo.png",
        Kind = ClientKind.Server
    };

    [Fact]
    public async Task AdminCreateClientAsync_PostsRequestAndReadsFlatCredentials()
    {
        _mockServer
            .Given(Request.Create().WithPath("/clients").UsingPost())
            .RespondWith(JsonResponse(201, $$"""
                {
                    "audience": "{{ClientId}}",
                    "kind": "server",
                    "token": "placeholder-token",
                    "encryption_key": "placeholder-key",
                    "client": {{ClientJson("placeholder-secret")}}
                }
                """));

        var client = await CreateClientAsync();
        var result = await client.AdminCreateClientAsync(ServerClientRequest());

        Assert.Equal(ClientKind.Server, result.Kind);
        Assert.Equal("placeholder-token", result.Token);
        Assert.Equal("placeholder-key", result.EncryptionKey);
        Assert.Equal(result.Client.Id, result.Audience);
        Assert.Equal("placeholder-secret", result.Client.Secret);

        var request = ClientsRequest();
        Assert.Equal("POST", request.Method);
        Assert.Equal("/clients", request.Path);
        AssertToken(request);

        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("billing-service", body.RootElement.GetProperty("name").GetString());
        Assert.Equal("server", body.RootElement.GetProperty("kind").GetString());
        Assert.Equal("https://billing.example.com/logo.png", body.RootElement.GetProperty("logo_url").GetString());
        Assert.False(body.RootElement.TryGetProperty("code_max_age", out _));
        Assert.False(body.RootElement.TryGetProperty("redirect_uri", out _));
    }

    [Fact]
    public async Task AdminCreateClientAsync_Throws_OnConflict()
    {
        _mockServer
            .Given(Request.Create().WithPath("/clients").UsingPost())
            .RespondWith(JsonResponse(409, """{"message":"client already exists"}"""));

        var client = await CreateClientAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.AdminCreateClientAsync(ServerClientRequest()));
        Assert.Contains("409", ex.Message);
    }

    [Fact]
    public async Task AdminListClientsAsync_SendsQueryWithEmptyFilter()
    {
        _mockServer
            .Given(Request.Create().WithPath("/clients/list").UsingMethod("QUERY"))
            .RespondWith(JsonResponse(200, $$"""
                {
                    "current_page": 1,
                    "page_size": 1,
                    "total_pages": 1,
                    "total_items": 1,
                    "has_next_page": false,
                    "items": [{{ClientJson(string.Empty)}}]
                }
                """));

        var client = await CreateClientAsync();
        var page = await client.AdminListClientsAsync(new PageOptions { Page = 1, Size = 100 });

        Assert.Equal(1, page.TotalItems);
        var item = Assert.Single(page.Items);
        Assert.Equal(ClientId, item.Id);
        Assert.True(string.IsNullOrEmpty(item.Secret));
        Assert.Equal(new DateTime(2026, 10, 13, 17, 50, 37), item.CreatedAt);
        Assert.Equal(new DateTime(2026, 10, 13, 18, 1, 2), item.UpdatedAt);
        Assert.Equal(new List<string> { "client_credentials" }, item.GrantTypes);
        Assert.Equal(604800, item.RefreshMaxAge);
        Assert.Equal(2, item.Version);

        var request = ClientsRequest();
        Assert.Equal("QUERY", request.Method);
        Assert.Equal("/clients/list", request.Path);
        Assert.Equal("1", Assert.Single(request.Query!["page"]));
        Assert.Equal("100", Assert.Single(request.Query!["size"]));
        Assert.False(request.Query!.ContainsKey("details"));
        AssertToken(request);

        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(JsonValueKind.Object, body.RootElement.ValueKind);
        Assert.Empty(body.RootElement.EnumerateObject());
    }

    [Fact]
    public async Task AdminListClientsAsync_SendsFilterBody()
    {
        _mockServer
            .Given(Request.Create().WithPath("/clients/list").UsingMethod("QUERY"))
            .RespondWith(JsonResponse(200, """{"current_page":1,"page_size":0,"total_pages":0,"total_items":0,"has_next_page":false,"items":[]}"""));

        var client = await CreateClientAsync();
        var page = await client.AdminListClientsAsync(new PageOptions { Page = 1, Size = 100 },
            new ClientFilter { Name = "billing", Sort = "created_at", SortDescending = true });

        Assert.Equal(0, page.TotalItems);
        Assert.Empty(page.Items);

        var request = ClientsRequest();
        Assert.Equal("QUERY", request.Method);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("billing", body.RootElement.GetProperty("name").GetString());
        Assert.Equal("created_at", body.RootElement.GetProperty("sort").GetString());
        Assert.True(body.RootElement.GetProperty("sort_descending").GetBoolean());
        Assert.False(body.RootElement.TryGetProperty("scope", out _));
    }

    [Fact]
    public async Task AdminCountClientsAsync_ReturnsTotalCount()
    {
        _mockServer
            .Given(Request.Create().WithPath("/clients/count").UsingGet())
            .RespondWith(JsonResponse(200, """{"total_count":7}"""));

        var client = await CreateClientAsync();
        var total = await client.AdminCountClientsAsync();

        Assert.Equal(7L, total);
        var request = ClientsRequest();
        Assert.Equal("GET", request.Method);
        Assert.Equal("/clients/count", request.Path);
        AssertToken(request);
    }

    [Fact]
    public async Task AdminGetClientAsync_EscapesIdAndReadsSecret()
    {
        _mockServer
            .Given(Request.Create().WithPath(p => p.StartsWith("/clients/")).UsingGet())
            .RespondWith(JsonResponse(200, ClientJson("placeholder-secret")));

        var client = await CreateClientAsync();
        var result = await client.AdminGetClientAsync("abc def/x");

        Assert.Equal(ClientId, result.Id);
        Assert.Equal("placeholder-secret", result.Secret);
        Assert.Equal("billing-service", result.Name);

        var request = ClientsRequest();
        Assert.Equal("GET", request.Method);
        var sent = _recorder.RequestUris.Single(u => u.AbsolutePath.StartsWith("/clients/"));
        Assert.Equal("/clients/abc%20def%2Fx", sent.AbsolutePath);
        AssertToken(request);
    }

    [Fact]
    public async Task AdminGetClientAsync_Throws_OnNotFound()
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}").UsingGet())
            .RespondWith(JsonResponse(404, """{"message":"client not found"}"""));

        var client = await CreateClientAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.AdminGetClientAsync(ClientId));
        Assert.Contains("404", ex.Message);
    }

    [Theory]
    [InlineData(204, true)]
    [InlineData(304, false)]
    public async Task AdminDeleteClientAsync_MapsNoContentStatus(int status, bool expected)
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}").UsingDelete())
            .RespondWith(Response.Create().WithStatusCode(status));

        var client = await CreateClientAsync();
        var deleted = await client.AdminDeleteClientAsync(ClientId);

        Assert.Equal(expected, deleted);
        var request = ClientsRequest();
        Assert.Equal("DELETE", request.Method);
        Assert.Equal($"/clients/{ClientId}", request.Path);
        AssertToken(request);
    }

    [Fact]
    public async Task AdminDeleteClientAsync_Throws_OnNotFound()
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}").UsingDelete())
            .RespondWith(JsonResponse(404, """{"message":"client not found"}"""));

        var client = await CreateClientAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.AdminDeleteClientAsync(ClientId));
        Assert.Contains("404", ex.Message);
    }

    [Fact]
    public async Task AdminIssueClientTokenAsync_UserKindHasNoEncryptionKey()
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}/token").UsingPost())
            .RespondWith(JsonResponse(200, $$"""{"audience":"{{ClientId}}","kind":"user","token":"placeholder-token"}"""));

        var client = await CreateClientAsync();
        var creds = await client.AdminIssueClientTokenAsync(ClientId);

        Assert.Equal(ClientId, creds.Audience);
        Assert.Equal(ClientKind.User, creds.Kind);
        Assert.Equal("placeholder-token", creds.Token);
        Assert.Null(creds.EncryptionKey);

        var request = ClientsRequest();
        Assert.Equal("POST", request.Method);
        Assert.Equal($"/clients/{ClientId}/token", request.Path);
        AssertToken(request);
    }

    [Fact]
    public async Task AdminRevokeClientTokensAsync_ReturnsTrue_OnNoContent()
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}/revoke-tokens").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(204));

        var client = await CreateClientAsync();
        Assert.True(await client.AdminRevokeClientTokensAsync(ClientId));

        var request = ClientsRequest();
        Assert.Equal("POST", request.Method);
        Assert.Equal($"/clients/{ClientId}/revoke-tokens", request.Path);
        AssertToken(request);
    }

    [Fact]
    public async Task AdminRevokeClientTokensAsync_Throws_OnNotFound()
    {
        _mockServer
            .Given(Request.Create().WithPath($"/clients/{ClientId}/revoke-tokens").UsingPost())
            .RespondWith(JsonResponse(404, """{"message":"client not found"}"""));

        var client = await CreateClientAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.AdminRevokeClientTokensAsync(ClientId));
        Assert.Contains("404", ex.Message);
    }
}
