using System.ComponentModel.DataAnnotations;

namespace JwtAuthGatewayApi.Models
{
    public class UpdateRoleRequest
    {
        [Required]
        public string Role { get; set; } = string.Empty;
    }
}