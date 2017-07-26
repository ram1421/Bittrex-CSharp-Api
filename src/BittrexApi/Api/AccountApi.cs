using Bittrex.Helpers;
using Bittrex.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Bittrex.Api
{
    public static class AccountApi
    {
        public static async Task<IList<BalanceModel>> GetAccountBalancesAsync(bool hideZeroBalances = false)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getbalances", true);
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve account balances. Message: {result.Message}");
            }
            var accountBalances = result.Result.Select(jsonObject => jsonObject.ToObject<BalanceModel>()).ToList();
            if (hideZeroBalances)
            {
                accountBalances = accountBalances.Where(accountBalance => accountBalance.Balance != 0).ToList();
            }

            return accountBalances;
        }

        public static async Task<BalanceModel> GetAccountBalanceAsync(string currency)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getbalance?currency={currency}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve account balance. Message: {result.Message}");
            }
            return result.Result.ToObject<BalanceModel>();
        }

        public static async Task<DepositAddressModel> GetDepositAddressAsync(string currency)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getdepositaddress?currency={currency}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to retrieve deposit address. Message: {result.Message}");
            }
            return result.Result.ToObject<DepositAddressModel>();
        }

        public static async Task<TrackingIdModel> WithdrawAsync(string currency, double quantity, string address, string paymentid)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/withdraw?currency={currency}&quantity={quantity}&address={address}" + (!string.IsNullOrEmpty(paymentid) ? $"&paymentid={paymentid}" : ""), true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to withdraw. Message: {result.Message}");
            }
            return result.Result.ToObject<TrackingIdModel>();
        }

        public static async Task<OrderModel> GetOrderAsync(Guid orderUuid)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getorder?uuid={orderUuid}", true);
            var result = JsonConvert.DeserializeObject<JsonResultWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to get order. Message: {result.Message}");
            }
            return result.Result.ToObject<OrderModel>();
        }

        public static async Task<IList<OrderHistoryModel>> GetOrderHistoryAsync(string market = null)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getorderhistory" + (!string.IsNullOrEmpty(market) ? $"?market={market}" : ""), true);
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to get order history. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<OrderHistoryModel>()).ToList();
        }

        public static async Task<IList<WithdrawlHistoryModel>> GetWithdrawalHistoryAsync(string currency = null)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getwithdrawalhistory" + (!string.IsNullOrEmpty(currency) ? $"?currency={currency}" : ""), true);
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to get withdrawal history. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<WithdrawlHistoryModel>()).ToList();
        }

        public static async Task<IList<DepositHistoryModel>> GetDepositHistoryAsync(string currency = null)
        {
            string responseStr = await HttpUtilities.GetHttpResponseAsync($"https://bittrex.com/api/v1.1/account/getdeposithistory" + (!string.IsNullOrEmpty(currency) ? $"?currency={currency}" : ""), true);
            var result = JsonConvert.DeserializeObject<JsonResultArrayWrapper>(responseStr);
            if (!result.Success)
            {
                throw new Exception($"Failed to get deposit history. Message: {result.Message}");
            }
            return result.Result.Select(jsonObject => jsonObject.ToObject<DepositHistoryModel>()).ToList();
        }
    }
}
