using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace Bittrex.Helpers
{
    internal class JsonResultArrayWrapper
    {
        [JsonProperty("result")]
        public IEnumerable<JObject> Result { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }

        [JsonProperty("success")]
        public bool Success { get; set; }
    }
}
