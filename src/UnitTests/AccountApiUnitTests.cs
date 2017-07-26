using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;
using Bittrex.Api;

namespace UnitTests
{
    [TestClass]
    public class AccountApiUnitTests
    {
        [TestMethod]
        public async Task TestGetAccountBalancesAsync()
        {
            var accountBalances = await AccountApi.GetAccountBalancesAsync();
            Assert.IsNotNull(accountBalances, "accountBalances is null 1");

            accountBalances = await AccountApi.GetAccountBalancesAsync(hideZeroBalances: true);
            Assert.IsNotNull(accountBalances, "accountBalances is null 2");
        }

        [TestMethod]
        public async Task TestGetAccountBalanceAsync()
        {
            var accountBalance = await AccountApi.GetAccountBalanceAsync("RISE");
            Assert.IsNotNull(accountBalance, "Account balance is null");
        }

        [TestMethod]
        public async Task TestGetDepositAddressAsync()
        {
            var depositAddress = await AccountApi.GetDepositAddressAsync("RISE");
            Assert.IsNotNull(depositAddress, "Deposit address is null");
        }

        [TestMethod]
        public async Task TestGetOrderAsync()
        {
            var order = await AccountApi.GetOrderAsync(new Guid("3f73784a-2d70-4923-ba9a-6e2fa5fc3c63"));
            Assert.IsNotNull(order, "order is null");
        }

        [TestMethod]
        public async Task TestGetOrderHistoryAsync()
        {
            var orderHistory = await AccountApi.GetOrderHistoryAsync();
            Assert.IsNotNull(orderHistory, "Order history is null");
        }

        [TestMethod]
        public async Task TestGetWithdrawalHistoryAsync()
        {
            var withdrawalHistory = await AccountApi.GetWithdrawalHistoryAsync();
            Assert.IsNotNull(withdrawalHistory, "Withdrawal history is null");
        }

        [TestMethod]
        public async Task TestGetDepositHistoryAsync()
        {
            var depositHistory = await AccountApi.GetDepositHistoryAsync();
            Assert.IsNotNull(depositHistory, "Deposit history is null");
        }
    }
}
