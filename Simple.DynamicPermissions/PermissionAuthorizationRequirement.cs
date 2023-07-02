using Microsoft.AspNetCore.Authorization;

namespace Simple.DynamicPolicyPermissions;
public class PermissionAuthorizationRequirement : IAuthorizationRequirement
{
    public PermissionAuthorizationRequirement(string permissions)
    {
        Permissions = permissions;
    }

    public string Permissions { get; }
}
