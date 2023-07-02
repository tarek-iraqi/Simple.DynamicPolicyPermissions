using Microsoft.AspNetCore.Authorization;

namespace Simple.DynamicPolicyPermissions;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
public class HasPermissionAttribute : AuthorizeAttribute
{
    public HasPermissionAttribute(params string[] permissions)
        : base(permissions is not null && permissions.Where(p => string.IsNullOrWhiteSpace(p) is false).Any()
             ? permissions
                .Where(p => string.IsNullOrWhiteSpace(p) is false)
                .Aggregate((a, b) => a + PermissionConstants.PermissionSeparator + b)
             : string.Empty)
    {
    }
}

