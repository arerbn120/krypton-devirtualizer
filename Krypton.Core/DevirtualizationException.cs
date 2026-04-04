using System;

namespace Krypton.Core
{
    public class DevirtualizationException : Exception
    {
        public DevirtualizationException(string message) : base(message)
        {
        }

        public DevirtualizationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}