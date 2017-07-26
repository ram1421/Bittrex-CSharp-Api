using System;

namespace Bittrex.Models
{
    public class OrderModel
    {
        public string AccountId { get; set; }
        public Guid OrderUuid { get; set; }
        public string Exchange { get; set; }
        public string Type { get; set; }
        public double Quantity { get; set; }
        public double QuantityRemaining { get; set; }
        public double Limit { get; set; }
        public double Reserved { get; set; }
        public double ReserveRemaining { get; set; }
        public double CommissionReserved { get; set; }
        public double CommissionReserveRemaining { get; set; }
        public double CommissionPaid { get; set; }
        public double Price { get; set; }
        public double? PricePerUnit { get; set; }
        public DateTime Opened { get; set; }
        public DateTime? Closed { get; set; }
        public bool IsOpen { get; set; }
        public Guid Sentinel { get; set; }
        public bool CancelInitiated { get; set; }
        public bool ImmediateOrCancel { get; set; }
        public bool IsConditional { get; set; }
        public string Condition { get; set; }
        public string ConditionTarget { get; set; }
    }
}
