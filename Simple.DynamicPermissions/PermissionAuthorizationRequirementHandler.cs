using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

namespace Simple.DynamicPolicyPermissions;
public class PermissionAuthorizationRequirementHandler : AuthorizationHandler<PermissionAuthorizationRequirement>
{
    private readonly IConfiguration _configuration;

    public PermissionAuthorizationRequirementHandler(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionAuthorizationRequirement requirement)
    {
        var superRoles = _configuration.GetSection("DynamicPolicyPermissions:SuperRoles").Get<List<string>>()
            ?? new() { PermissionConstants.SUPER_ADMIN };

        var isAuthorized = superRoles.Any(context.User.IsInRole);

        if (isAuthorized)
        {
            context.Succeed(requirement);

            return Task.CompletedTask;
        }

        if (requirement.Permissions.Contains(PermissionConstants.PermissionGroupSeparator))
        {
            var permissionGroupsString = requirement.Permissions.Split(PermissionConstants.PermissionSeparator);

            var permissionGroups = permissionGroupsString
                .Select(x => x.Split(PermissionConstants.PermissionGroupSeparator));

            foreach (var group in permissionGroups)
            {
                isAuthorized = !group.Except(
                    context.User.Claims.Where(x => x.Type == PermissionConstants.ActionPermission)
                        .Select(x => x.Value)).Any();

                if (isAuthorized) break;
            }
        }
        else if (requirement.Permissions.Contains(PermissionConstants.PermissionSeparator))
        {
            var permissions = requirement.Permissions
                .Split(PermissionConstants.PermissionSeparator);

            isAuthorized = context.User.Claims
                .Where(x => x.Type == PermissionConstants.ActionPermission)
                .Any(x => permissions.Contains(x.Value));
        }
        else
        {
            isAuthorized = context.User.Claims
                .Any(x => x.Type == PermissionConstants.ActionPermission && x.Value == requirement.Permissions);
        }

        if (isAuthorized)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}