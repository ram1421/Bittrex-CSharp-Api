using Bittrex.Helpers;
using Bittrex.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Bittrex.Api
{
    public static class MarketApi
    {
        public static async Task<TrackingIdModel> BuyLimitAsync(string market, double quantity, double rate)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/market/buylimit?market={market}&quantity={quantity}&rate={rate}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to buy limit. Message: {result.Message}");
            }
            return result.Result.ToObject<TrackingIdModel>();
        }

        public static async Task<TrackingIdModel> SellLimitAsync(string market, double quantity, double rate)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/market/selllimit?market={market}&quantity={quantity}&rate={rate}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to sell limit. Message: {result.Message}");
            }
            return result.Result.ToObject<TrackingIdModel>();
        }

        public static async Task CancelOrder(Guid orderUuid)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/market/cancel?uuid={orderUuid}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to sell limit. Message: {result.Message}");
            }
        }

        public static async Task<IList<OpenOrderModel>> GetOpenOrdersAsync(string market = null)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/market/getopenorders" + (!string.IsNullOrEmpty(market) ? $"?market={market}" : ""), true);
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to get open orders. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<OpenOrderModel>()).ToList();
        }
    }
}
