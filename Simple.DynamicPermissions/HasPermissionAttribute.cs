using Microsoft.AspNetCore.Authorization;

namespace Simple.DynamicPolicyPermissions;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
public class HasPermissionAttribute : AuthorizeAttribute
{
    public HasPermissionAttribute(params string[] permissions)
        : base(permissions.Aggregate((a, b) => a + PermissionConstants.PermissionSeparator + b))
    { }
}

