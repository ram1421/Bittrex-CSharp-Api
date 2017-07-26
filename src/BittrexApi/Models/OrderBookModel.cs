using System.Collections.Generic;

namespace Bittrex.Models
{
    public class OrderBookModel
    {
        public IList<Order> Buy { get; set; }
        public IList<Order> Sell { get; set; }
    }

    public class Order
    {
        public double Quantity { get; set; }
        public double Rate { get; set; }
    }
}
