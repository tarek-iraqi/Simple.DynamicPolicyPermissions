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

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithoutPermissions_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasNoPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithSuperAdminRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasSuperAdminRoleToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithConfigurableSuperRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasConfigurableSuperRoleToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithEditUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasEditUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PutAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithEditUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasEditUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PutAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithViewAllUsersPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasViewAllUsersPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserAndViewAllUsersPermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserAndViewAllUsersPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasDeleteUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddEditPermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddEditPermissionGroupToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithViewDeletePermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasViewDeletePermissionGroupToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWithOnePermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddUserPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWith3Permissions_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHas3PermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWith4Permissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHas4PermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetUserStatus_AnonymousUserAndEmptyPermissionValue_ReturnUnAuthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("api/users/1/status");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetUserStatus_AuthenticatedUserAndEmptyPermissionValue_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasNoPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1/status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetUserAddress_AnonymousUserAndNullPermissionValue_ReturnUnAuthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("api/users/1/address");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetUserAddress_AuthenticatedUserAndNullPermissionValue_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasNoPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1/address");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetUserEmail_AnonymousUserAndNoPermissionValue_ReturnUnAuthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("api/users/1/email");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetUserEmail_AuthenticatedUserAndNoPermissionValue_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasNoPermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/users/1/email");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetRoles_AuthenticatedUserWithManageRolesPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasManageRolesPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.GetAsync("api/roles");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithManageRolesPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasManageRolesPermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/roles", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithAddRolePermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasAddRolePermissionToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/roles", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithManageRolesAndAddRolePermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        var token = Helpers.UserHasManageRoleAndAddRolePermissionsToken();

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsync("api/roles", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}