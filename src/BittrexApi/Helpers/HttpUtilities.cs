using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bittrex.Helpers
{
    public static class HttpUtilities
    {
        public static ConfigRetrieverBase ConfigRetriever { get; set; } = new ConfigRetrieverRegistry();

        public static async Task<string> GetHttpResponseAsync(string url, bool sendApiSign = false)
        {
            string apiSignString = string.Empty;
            var apiKeyAndSecret = ConfigRetriever.GetApiAndSecret();
            var apiKey = apiKeyAndSecret.Item1;
            var apiSecret = apiKeyAndSecret.Item2;

            if (sendApiSign)
            {
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    var nonce = (long)((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds);
                    using (HMACSHA512 hmac = new HMACSHA512(Encoding.UTF8.GetBytes(apiSecret)))
                    {
                        if (string.IsNullOrEmpty(new Uri(url).Query))
                        {
                            url = $"{url}?apikey={apiKey}&nonce={nonce}";
                        }
                        else
                        {
                            url = $"{url}&apikey={apiKey}&nonce={nonce}";
                        }

                        var hash = hmac.ComputeHash(new MemoryStream(Encoding.UTF8.GetBytes(url)));
                        apiSignString = String.Concat(Array.ConvertAll(hash, x => x.ToString("X2")));
                    }
                }
            }

            var client = new HttpClient();

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrEmpty(apiSignString))
            {
                requestMessage.Headers.Add("apisign", apiSignString);
            }

            var response = await client.SendAsync(requestMessage);
            if (!response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();

                var message = $"Request failed with HTTP status {response.StatusCode} ({response.ReasonPhrase})\n{responseContent}";

                throw new Exception($"{(int)response.StatusCode} {message}");
            }
            return await response.Content.ReadAsStringAsync();
        }
    }
}
