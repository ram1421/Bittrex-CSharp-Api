using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Bittrex.Helpers
{
    internal class JsonResultWrapper
    {
        [JsonProperty("result")]
        public JObject Result { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }

        [JsonProperty("success")]
        public bool Success { get; set; }
    }
}
