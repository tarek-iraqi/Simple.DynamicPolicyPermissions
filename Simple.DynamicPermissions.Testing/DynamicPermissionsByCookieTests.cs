using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Newtonsoft.Json;
using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPermissions.TestWebApi.Controllers;
using Simple.DynamicPolicyPermissions;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace Simple.DynamicPermissions.Testing;
public class DynamicPermissionsByCookieTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public DynamicPermissionsByCookieTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }


    [Fact]
    public async Task AddUser_NoAuthenticatedUser_ReturnUnauthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithoutPermissions_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, Enumerable.Empty<Claim>());

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithSuperAdminRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Role, PermissionConstants.SUPER_ADMIN)
        };

        await PerformLogin(client, claims);

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithConfigurableSuperRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Role, "SUPER_USER")
        };

        await PerformLogin(client, claims);

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser)
        };

        await PerformLogin(client, claims);

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithEditUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

        await PerformLogin(client, claims);

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser)
        };

        await PerformLogin(client, claims);

        var response = await client.PutAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithEditUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

        await PerformLogin(client, claims);

        var response = await client.PutAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser)
        };

        await PerformLogin(client, claims);

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithViewAllUsersPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        await PerformLogin(client, claims);

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserAndViewAllUsersPermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        await PerformLogin(client, claims);

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser)
        };

        await PerformLogin(client, claims);

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser)
        };

        await PerformLogin(client, claims);

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddEditPermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

        await PerformLogin(client, claims);

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithViewDeletePermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        await PerformLogin(client, claims);

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private async Task PerformLogin(HttpClient client, IEnumerable<Claim> claims)
    {
        var user = new UserLoginModel
        {
            UserClaims = claims.Select(c => new UserClaims { Key = c.Type, Value = c.Value }).ToList()
        };

        string strPayload = JsonConvert.SerializeObject(user);
        var content = new StringContent(strPayload, Encoding.UTF8, "application/json");

        var res = await client.PostAsync("api/account/login", content);
    }
}
