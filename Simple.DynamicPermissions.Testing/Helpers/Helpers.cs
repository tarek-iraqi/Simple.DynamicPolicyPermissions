using Microsoft.IdentityModel.Tokens;
using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPolicyPermissions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Simple.DynamicPermissions.Testing;
public static class Helpers
{
    public static string UserHasNoPermissionsToken()
    {
        return GenerateAccessToken(Enumerable.Empty<Claim>());
    }

    public static string UserHasSuperAdminRoleToken()
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Role, PermissionConstants.SUPER_ADMIN)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasConfigurableSuperRoleToken()
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Role, "SUPER_USER")
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasAddUserPermissionToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasEditUserPermissionToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasDeleteUserPermissionToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasViewAllUsersPermissionToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasDeleteUserAndViewAllUsersPermissionsToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasAddEditPermissionGroupToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

        return GenerateAccessToken(claims);
    }

    public static string UserHasViewDeletePermissionGroupToken()
    {
        var claims = new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

        return GenerateAccessToken(claims);
    }

    private static string GenerateAccessToken(IEnumerable<Claim> userClaims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("35ffc99e-59f8-4b85-97f5-1df3c76d9ea4"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var token = new JwtSecurityToken
        (
            "webapi",
            "webapi",
            userClaims.GroupBy(x => x.Value).Select(y => y.First()).Distinct(),
            DateTime.Now,
            DateTime.Now.AddMinutes(10),
            credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}