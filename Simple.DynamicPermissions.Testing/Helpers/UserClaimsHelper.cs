using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPolicyPermissions;
using System.Security.Claims;

namespace Simple.DynamicPermissions.Testing;
internal class UserClaimsHelper
{
    internal static IEnumerable<Claim> SuperAdminRoleClaim
        => new List<Claim>
        {
            new Claim(ClaimTypes.Role, PermissionConstants.SUPER_ADMIN)
        };

    internal static IEnumerable<Claim> ConfigurableSuperRoleClaim
        => new List<Claim>
        {
            new Claim(ClaimTypes.Role, "SUPER_USER")
        };

    internal static IEnumerable<Claim> AddUserPermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser)
        };

    internal static IEnumerable<Claim> EditUserPermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

    internal static IEnumerable<Claim> DeleteUserPermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser)
        };

    internal static IEnumerable<Claim> ViewAllUsersPermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

    internal static IEnumerable<Claim> DeleteUserAndViewAllUsersPermissionsClaims
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

    internal static IEnumerable<Claim> AddEditPermissionGroupClaims
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
        };

    internal static IEnumerable<Claim> ViewDeletePermissionGroupClaims
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers)
        };

    internal static IEnumerable<Claim> ThreePermissionsClaims
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser)
        };

    internal static IEnumerable<Claim> FourPermissionsClaims
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.EditUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.DeleteUser),
            new Claim(PermissionConstants.ActionPermission, Permissions.ViewAllUsers),
        };

    internal static IEnumerable<Claim> ManageRolesPermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.ManageRoles)
        };

    internal static IEnumerable<Claim> AddRolePermissionClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.AddRole)
        };

    internal static IEnumerable<Claim> ManageRoleAndAddRolePermissionsClaim
        => new List<Claim>
        {
            new Claim(PermissionConstants.ActionPermission, Permissions.ManageRoles),
            new Claim(PermissionConstants.ActionPermission, Permissions.AddRole)
        };
}
