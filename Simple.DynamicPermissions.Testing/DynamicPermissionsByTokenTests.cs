using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;

namespace Simple.DynamicPermissions.Testing;

public class DynamicPermissionsByTokenTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public DynamicPermissionsByTokenTests(WebApplicationFactory<Program> factory)
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

        var token = Helpers.UserHasNoPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithSuperAdminRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasSuperAdminRoleToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithConfigurableSuperRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasConfigurableSuperRoleToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithEditUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasEditUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PutAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithEditUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasEditUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PutAsync("api/user", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithViewAllUsersPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasViewAllUsersPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserAndViewAllUsersPermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserAndViewAllUsersPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddEditPermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddEditPermissionGroupToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithViewDeletePermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasViewDeletePermissionGroupToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/user");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}