using System.Collections.Concurrent;

namespace JwtAuthGatewayApi.Services
{
    public class TokenBlacklistService
    {
        // ConcurrentBag is a thread-safe list perfect for a simple in-memory blacklist
        private readonly ConcurrentBag<string> _blacklistedJtis = new ConcurrentBag<string>();

        // Adds a token's unique ID to the blacklist upon logout
        public void BlacklistToken(string jti)
        {
            if (!string.IsNullOrEmpty(jti))
            {
                _blacklistedJtis.Add(jti);
            }
        }

        // Checks if a token's unique ID exists in our blacklist
        public bool IsTokenBlacklisted(string jti)
        {
            if (string.IsNullOrEmpty(jti))
            {
                return false;
            }
            return _blacklistedJtis.Contains(jti);
        }
    }
}