using System;

namespace Bittrex.Models
{
    public class BalanceModel
    {
        public string Currency { get; set; }
        public double? Balance { get; set; }
        public double? Available { get; set; }
        public double? Pending { get; set; }
        public string CryptoAddress { get; set; }
        public bool Requested { get; set; }
        public Guid? Uuid { get; set; }
    }
}
