using Bittrex.Helpers;
using Bittrex.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Bittrex.Api
{
    public static class PublicApi
    {
        public static async Task<IList<MarketModel>> GetMarketsAsync()
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync("https://bittrex.com/api/v1.1/public/getmarkets");
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve markets. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<MarketModel>()).ToList();
        }

        public static async Task<IList<CurrencyModel>> GetCurrenciesAsync()
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync("https://bittrex.com/api/v1.1/public/getcurrencies");
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve currencies. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<CurrencyModel>()).ToList();
        }

        public static async Task<TickerModel> GetTickerAsync(string market)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/public/getticker?market={market}");
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve ticker. Message: {result.Message}");
            }
            return result.Result.ToObject<TickerModel>();
        }

        public static async Task<IList<MarketSummaryModel>> GetMarketSummariesAsync()
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/public/getmarketsummaries");
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve market summaries. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<MarketSummaryModel>()).ToList();
        }

        public static async Task<MarketSummaryModel> GetMarketSummaryAsync(string market)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/public/getmarketsummary?market={market}");
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve market summary. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<MarketSummaryModel>()).FirstOrDefault();
        }

        public static async Task<OrderBookModel> GetOrderBookAsync(string market, string type, int depth)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/public/getorderbook?market={market}&type={type}&depth={depth}");
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve order book. Message: {result.Message}");
            }
            return result.Result.ToObject<OrderBookModel>();
        }

        public static async Task<IList<MarketHistoryModel>> GetMarketHistoryAsync(string market)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/public/getmarkethistory?market={market}");
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve market history. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<MarketHistoryModel>()).ToList();
        }
    }
}
