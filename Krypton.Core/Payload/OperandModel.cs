using System;
using System.Collections.Generic;

namespace Krypton.Core.Payload
{
    public sealed class OperandModel
    {
        private readonly OperandDescriptor[] _descriptors;

        public OperandModel(OperandDescriptor[] descriptors)
        {
            _descriptors = descriptors ?? Array.Empty<OperandDescriptor>();
        }

        public IReadOnlyList<OperandDescriptor> Descriptors => _descriptors;
        public int Count => _descriptors.Length;

        public OperandDescriptor this[int vmByte] => _descriptors[vmByte];

        public bool TryGetDescriptor(int vmByte, out OperandDescriptor descriptor)
        {
            if (vmByte >= 0 && vmByte < _descriptors.Length)
            {
                descriptor = _descriptors[vmByte];
                return descriptor != null;
            }

            descriptor = null;
            return false;
        }
    }
}
