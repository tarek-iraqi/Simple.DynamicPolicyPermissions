using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Newtonsoft.Json;
using Simple.DynamicPermissions.TestWebApi.Controllers;
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

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithoutPermissions_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, Enumerable.Empty<Claim>());

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithSuperAdminRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.SuperAdminRoleClaim);

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithConfigurableSuperRole_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ConfigurableSuperRoleClaim);

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddUserPermissionClaim);

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddUser_AuthenticatedUserWithEditUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.EditUserPermissionClaim);

        var response = await client.PostAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithAddUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddUserPermissionClaim);

        var response = await client.PutAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EditUser_AuthenticatedUserWithEditUserPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.EditUserPermissionClaim);

        var response = await client.PutAsync("api/users", default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.DeleteUserPermissionClaim);

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithViewAllUsersPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ViewAllUsersPermissionClaim);

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task DeleteUser_AuthenticatedUserWithDeleteUserAndViewAllUsersPermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.DeleteUserAndViewAllUsersPermissionsClaims);

        var response = await client.DeleteAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddUserPermissionClaim);

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithDeleteUserPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.DeleteUserPermissionClaim);

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithAddEditPermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddEditPermissionGroupClaims);

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewAllUsers_AuthenticatedUserWithViewDeletePermissionGroup_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ViewDeletePermissionGroupClaims);

        var response = await client.GetAsync("api/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWithOnePermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddUserPermissionClaim);

        var response = await client.GetAsync("api/users/1");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWith3Permissions_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ThreePermissionsClaims);

        var response = await client.GetAsync("api/users/1");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetUserDetails_AuthenticatedUserWith4Permissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.FourPermissionsClaims);

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

        await PerformLogin(client, Enumerable.Empty<Claim>());

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

        await PerformLogin(client, Enumerable.Empty<Claim>());

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

        await PerformLogin(client, Enumerable.Empty<Claim>());

        var response = await client.GetAsync("api/users/1/email");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetRoles_AuthenticatedUserWithManageRolesPermission_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ManageRolesPermissionClaim);

        var response = await client.GetAsync("api/roles");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithManageRolesPermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ManageRolesPermissionClaim);

        var response = await client.PostAsync("api/roles", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithAddRolePermission_ReturnForbidden()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.AddRolePermissionClaim);

        var response = await client.PostAsync("api/roles", default);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AddRole_AuthenticatedUserWithManageRolesAndAddRolePermissions_ReturnOk()
    {
        var client = _factory.CreateClient();

        await PerformLogin(client, UserClaimsHelper.ManageRoleAndAddRolePermissionsClaim);

        var response = await client.PostAsync("api/roles", default);

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
