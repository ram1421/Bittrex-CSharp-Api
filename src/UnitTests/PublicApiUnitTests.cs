using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;
using Bittrex.Api;

namespace UnitTests
{
    [TestClass]
    public class PublicApiUnitTests
    {
        [TestMethod]
        public async Task TestGetMarketsAsync()
        {
            var markets = await PublicApi.GetMarketsAsync();
            Assert.IsTrue(markets.Count > 0, "Markets count is zero");
        }

        [TestMethod]
        public async Task TestGetCurrenciesAsync()
        {
            var currencies = await PublicApi.GetCurrenciesAsync();
            Assert.IsTrue(currencies.Count > 0, "Currecies count is zero");
        }

        [TestMethod]
        public async Task TestGetTickerAsync()
        {
            var ticker = await PublicApi.GetTickerAsync("BTC-LTC");
            Assert.IsNotNull(ticker, "ticker is null");
        }

        [TestMethod]
        public async Task TestGetMarketSummariesAsync()
        {
            var marketSummaries = await PublicApi.GetMarketSummariesAsync();
            Assert.IsTrue(marketSummaries.Count > 0, "Market summaries count is zero");
        }

        [TestMethod]
        public async Task TestGetMarketSummaryAsync()
        {
            var marketSummary = await PublicApi.GetMarketSummaryAsync("BTC-LTC");
            Assert.IsNotNull(marketSummary, "Market summary is null");
        }

        [TestMethod]
        public async Task TestGetOrderBookAsync()
        {
            var orderBook = await PublicApi.GetOrderBookAsync("BTC-LTC", "both", 50);
            Assert.IsNotNull(orderBook, "OrderBook is null");
        }

        [TestMethod]
        public async Task TestGetMarketHistoryAsync()
        {
            var marketHistory = await PublicApi.GetMarketHistoryAsync("BTC-LTC");
            Assert.IsTrue(marketHistory.Count > 0, "Market history count is zero");
        }
    }
}
