using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Simple.DynamicPolicyPermissions;
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDynamicPolicyPermissions(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationPolicyProvider, AuthorizationPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationRequirementHandler>();

        return services;
    }
}
