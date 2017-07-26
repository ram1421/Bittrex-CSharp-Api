using Bittrex.Api;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestClass]
    class MarketApiUnitTests
    {
        [TestMethod]
        public async Task TestGetOpenOrdersAsync()
        {
            var openOrders = await MarketApi.GetOpenOrdersAsync();
            Assert.IsNotNull(openOrders, "openOrders is null");
        }
    }
}
