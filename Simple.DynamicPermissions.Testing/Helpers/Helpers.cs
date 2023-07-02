using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Simple.DynamicPermissions.Testing;
internal static class Helpers
{
    internal static string UserHasNoPermissionsToken()
        => GenerateAccessToken(Enumerable.Empty<Claim>());

    internal static string UserHasSuperAdminRoleToken()
        => GenerateAccessToken(UserClaimsHelper.SuperAdminRoleClaim);

    internal static string UserHasConfigurableSuperRoleToken()
        => GenerateAccessToken(UserClaimsHelper.ConfigurableSuperRoleClaim);

    internal static string UserHasAddUserPermissionToken()
        => GenerateAccessToken(UserClaimsHelper.AddUserPermissionClaim);

    internal static string UserHasEditUserPermissionToken()
        => GenerateAccessToken(UserClaimsHelper.EditUserPermissionClaim);

    internal static string UserHasDeleteUserPermissionToken()
        => GenerateAccessToken(UserClaimsHelper.DeleteUserPermissionClaim);

    internal static string UserHasViewAllUsersPermissionToken()
        => GenerateAccessToken(UserClaimsHelper.ViewAllUsersPermissionClaim);

    internal static string UserHasDeleteUserAndViewAllUsersPermissionsToken()
        => GenerateAccessToken(UserClaimsHelper.DeleteUserAndViewAllUsersPermissionsClaims);

    internal static string UserHasAddEditPermissionGroupToken()
        => GenerateAccessToken(UserClaimsHelper.AddEditPermissionGroupClaims);

    internal static string UserHasViewDeletePermissionGroupToken()
        => GenerateAccessToken(UserClaimsHelper.ViewDeletePermissionGroupClaims);

    internal static string UserHas3PermissionsToken()
        => GenerateAccessToken(UserClaimsHelper.ThreePermissionsClaims);

    internal static string UserHas4PermissionsToken()
        => GenerateAccessToken(UserClaimsHelper.FourPermissionsClaims);

    internal static string UserHasManageRolesPermissionToken()
        => GenerateAccessToken(UserClaimsHelper.ManageRolesPermissionClaim);

    internal static string UserHasAddRolePermissionToken()
        => GenerateAccessToken(UserClaimsHelper.AddRolePermissionClaim);

    internal static string UserHasManageRoleAndAddRolePermissionsToken()
        => GenerateAccessToken(UserClaimsHelper.ManageRoleAndAddRolePermissionsClaim);

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
            DateTime.Now.AddMinutes(60),
            credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}