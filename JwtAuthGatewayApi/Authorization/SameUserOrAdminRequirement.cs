using Microsoft.AspNetCore.Authorization;

namespace JwtAuthGatewayApi.Authorization
{
    public class SameUserOrAdminRequirement : IAuthorizationRequirement
    {
    }
}