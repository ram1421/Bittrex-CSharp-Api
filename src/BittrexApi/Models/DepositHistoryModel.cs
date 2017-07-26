using System;

namespace Bittrex.Models
{
    public class DepositHistoryModel
    {
        public Guid PaymentUuid { get; set; }
        public string Currency { get; set; }
        public double Amount { get; set; }
        public string Address { get; set; }
        public DateTime Opened { get; set; }
        public bool Authorized { get; set; }
        public bool PendingPayment { get; set; }
        public double TxCost { get; set; }
        public string TxId { get; set; }
        public bool Canceled { get; set; }
        public bool InvalidAddress { get; set; }
    }
}
