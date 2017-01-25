using System;

namespace MySafeGUI
{
    public class EventValue : EventArgs
    {
        public object Value { get; set; }
        public string pName { get; set; }
        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="value"></param>
        /// <param name="pName"></param>
        public EventValue(object value, string pName = null)
        {
            Value = value;
            this.pName = pName;
        }
    }
}