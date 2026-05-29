using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuthGatewayApi.Authorization
{
    // This handler checks the logged-in user against the requested user ID string
    public class SameUserOrAdminHandler : AuthorizationHandler<SameUserOrAdminRequirement, string>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            SameUserOrAdminRequirement requirement,
            string resourceUserId)
        {
            // 1. Extract the logged-in user's unique ID from the JWT claims token
            var loggedInUserId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // 2. Extract the logged-in user's role from the JWT claims token
            var loggedInUserRole = context.User.FindFirst(ClaimTypes.Role)?.Value;

            // 3. Condition: If the user is a SuperAdmin, grant full access instantly
            if (loggedInUserRole == "SuperAdmin")
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // 4. Condition: If the logged-in user ID matches the target resource ID, grant access
            if (!string.IsNullOrEmpty(loggedInUserId) && loggedInUserId == resourceUserId)
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // If neither condition is met, authorization fails implicitly (403 Forbidden)
            return Task.CompletedTask;
        }
    }
}