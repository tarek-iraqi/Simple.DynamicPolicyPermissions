using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

namespace Simple.DynamicPolicyPermissions;
public class AuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
{
    private readonly ConcurrentDictionary<string, AuthorizationPolicy> _policies;
    private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;

    public AuthorizationPolicyProvider(IOptions<AuthorizationOptions> options,
        IAuthenticationSchemeProvider authenticationSchemeProvider)
        : base(options)
    {
        _policies = new ConcurrentDictionary<string, AuthorizationPolicy>();
        _authenticationSchemeProvider = authenticationSchemeProvider;
    }

    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        var policy = await base.GetPolicyAsync(policyName);

        if (policy != null) return policy;

        _policies.TryGetValue(policyName, out policy);

        if (policy != null) return policy;

        var schemes = (await _authenticationSchemeProvider.GetAllSchemesAsync())
            .Select(scheme => scheme.Name)
            .ToArray();

        policy = new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(schemes)
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionAuthorizationRequirement(policyName))
            .Build();

        _policies.TryAdd(policyName, policy);

        return policy;
    }
}
