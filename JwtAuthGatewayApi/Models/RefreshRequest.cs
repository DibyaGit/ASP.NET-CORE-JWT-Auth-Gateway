using System.ComponentModel.DataAnnotations;

namespace JwtAuthGatewayApi.Models
{
    public class RefreshRequest
    {
        [Required]
        public string ExpiredAccessToken { get; set; } = string.Empty;

        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}