using Simple.DynamicPolicyPermissions;

namespace Simple.DynamicPermissions.TestWebApi.AppPermissions;

public static class Permissions
{
    public const string AddUser = "1";
    public const string EditUser = "2";
    public const string DeleteUser = "3";
    public const string ViewAllUsers = "4";

    public const string AddEditGroup = $"{AddUser}{PermissionConstants.PermissionGroupSeparator}{EditUser}";
    public const string ViewDeleteGroup = $"{ViewAllUsers}{PermissionConstants.PermissionGroupSeparator}{DeleteUser}";
}
