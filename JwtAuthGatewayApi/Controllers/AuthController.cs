using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtAuthGatewayApi.Models;
using JwtAuthGatewayApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthGatewayApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly TokenService _tokenService;
        private readonly TokenBlacklistService _blacklistService;
        private readonly IDataProtector _protector;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            TokenService tokenService,
            TokenBlacklistService blacklistService,
            IDataProtectionProvider protectionProvider)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _blacklistService = blacklistService;
            // Create a secure purpose-string protector for data protection compliance
            _protector = protectionProvider.CreateProtector("Gateway.RefreshToken.Protector");
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!await _roleManager.RoleExistsAsync(request.Role))
            {
                return BadRequest(new { message = "Requested role does not exist in system configuration." });
            }

            var userExists = await _userManager.FindByNameAsync(request.Username);
            if (userExists != null)
            {
                return BadRequest(new { message = "Username is already taken." });
            }

            var user = new ApplicationUser
            {
                UserName = request.Username,
                Email = request.Email
            };

            // Creates the account and automatically hashes the password internally
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            await _userManager.AddToRoleAsync(user, request.Role);

            return Ok(new { message = "User registered successfully with the specified role." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                return Unauthorized(new { error = "Unauthorized", message = "Invalid credentials provided.", code = 401 });
            }

            // Check if the account is currently locked due to previous brute-force attempts
            if (await _userManager.IsLockedOutAsync(user))
            {
                return StatusCode(423, new { message = "Account is locked out due to 5 failed attempts. Try again in 10 minutes." });
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!isPasswordValid)
            {
                // Access failed: increment count to track potential brute-force attempts
                await _userManager.AccessFailedAsync(user);
                return Unauthorized(new { error = "Unauthorized", message = "Invalid credentials provided.", code = 401 });
            }

            // Reset failed counter on successful authentication access
            await _userManager.ResetAccessFailedCountAsync(user);

            var roles = await _userManager.GetRolesAsync(user);
            var userRole = roles.FirstOrDefault() ?? "Employee";

            string jti = Guid.NewGuid().ToString();
            string accessToken = _tokenService.GenerateAccessToken(user, userRole, jti);
            string rawRefreshToken = _tokenService.GenerateRefreshToken();

            // Secure the raw token using Data Protection API before database storage
            user.RefreshToken = _protector.Protect(rawRefreshToken);
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                accessToken = accessToken,
                refreshToken = rawRefreshToken,
                expiresIn = 900,
                tokenType = "Bearer"
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            try
            {
                var principal = _tokenService.GetPrincipalFromExpiredToken(request.ExpiredAccessToken);
                var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    return BadRequest(new { message = "Invalid access token payload contents." });
                }

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || string.IsNullOrEmpty(user.RefreshToken))
                {
                    return Unauthorized(new { message = "Session data could not be verified." });
                }

                if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                {
                    return Unauthorized(new { error = "Unauthorized", message = "Token has expired. Please refresh your session.", code = 401 });
                }

                // Decrypt database stored value to verify against client's submitted raw token
                string decryptedStoredToken = _protector.Unprotect(user.RefreshToken);
                if (decryptedStoredToken != request.RefreshToken)
                {
                    return Unauthorized(new { message = "Invalid session token assignment." });
                }

                var roles = await _userManager.GetRolesAsync(user);
                var userRole = roles.FirstOrDefault() ?? "Employee";

                string newJti = Guid.NewGuid().ToString();
                string newAccessToken = _tokenService.GenerateAccessToken(user, userRole, newJti);
                string newRawRefreshToken = _tokenService.GenerateRefreshToken();

                // Rotate the used refresh token with a brand new protected pair
                user.RefreshToken = _protector.Protect(newRawRefreshToken);
                await _userManager.UpdateAsync(user);

                return Ok(new
                {
                    accessToken = newAccessToken,
                    refreshToken = newRawRefreshToken,
                    expiresIn = 900
                });
            }
            catch
            {
                return BadRequest(new { message = "Token processing verification encounter failure." });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            // Extract the unique token JTI ID from the claim payload
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

            if (!string.IsNullOrEmpty(jti))
            {
                // Place into memory store to instantly drop and invalidate this token instance
                _blacklistService.BlacklistToken(jti);
            }

            var userId = _userManager.GetUserId(User);
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    // Erase refresh tokens from records upon formal exit request
                    user.RefreshToken = null;
                    await _userManager.UpdateAsync(user);
                }
            }

            return Ok(new { message = "Logged out successfully. Token context has been destroyed." });
        }
    }
}