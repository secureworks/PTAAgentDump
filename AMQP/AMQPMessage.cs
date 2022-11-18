using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Secureworks.AMQP
{
    public enum AMQPProtocol
    {
        AMQP = 0,
        TLS = 2,
        SASL = 3
    }

    public enum AMQPMessageType
    {
        SASLInit = 0x41,
        AMQPOpen = 0x10,
        AMQPBegin = 0x11,
        AMQPAttach = 0x12,
        AMQPFlow = 0x13,
        AMQPTransfer = 0x14,
        AMQPDisposition = 0x15,
        AMQPDetach = 0x16,
        AMQPEnd = 0x17,
        AMQPClose = 0x18
    }

    public enum SASLMechanics
    {
        EXTERNAL,
        MSSBCBS,
        PLAIN,
        ANONYMOUS
    }

    

    public class SASLInit : AMQPMessage
    {
        private static string[] mechanicsValues = { "EXTERNAL", "MSSBCBS", "PLAIN", "ANONYMOUS" };
        public SASLInit(SASLMechanics mechanics = SASLMechanics.EXTERNAL)
        {
            AMQPList list = new AMQPList();
            list.Add(new AMQPSymbol(mechanicsValues[(int)mechanics])); // Mechanics
            list.Add(new AMQPNull()); // Initial response
            list.Add(new AMQPNull()); // Hostname
              
            base.Init(AMQPMessageType.SASLInit, list);
        }
    }

    public class AMQPDisconnect : AMQPMessage
    {
        public AMQPDisconnect()
        {
            base.WriteByte(0x07);
        }
    }

    public class AMQPEmpty : AMQPMessage
    {
        public AMQPEmpty()
        {
            base.WriteUInt32(8); // size
            base.WriteByte(2);
            base.WriteByte(0);
            base.WriteByte(0);
            base.WriteByte(0);
        }
    }

    public class AMQPDisposition : AMQPMessage
    {
        public AMQPDisposition(bool isInput, int state, int first=0)
        {
            AMQPItem direction = new AMQPFalse();
            if (isInput)
                direction = new AMQPTrue(); 

            // Ref: http://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html#type-disposition
            AMQPList list = new AMQPList();
            list.Add(direction); // role
            list.Add(new AMQPSmallUInt((byte)first)); // first
            list.Add(new AMQPNull()); // last
            list.Add(new AMQPTrue()); // settled
            list.Add(new AMQPConstructor(new AMQPSmallULong ((byte)state), new AMQPList())); // state
            list.Add(new AMQPNull()); // batchable

            base.Init(AMQPMessageType.AMQPDisposition, list);
        }
    }
    public class AMQPFlow : AMQPMessage
    {
        public AMQPFlow(int handle, int nextIncomingId = 1, int nextOutgoingId = 1, int linkCredit=1000)
        {
            // Ref: http://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html#type-flow
            AMQPList list = new AMQPList();
            list.Add(new AMQPSmallUInt((byte)nextIncomingId)); // next-incoming-id
            list.Add(new AMQPUInt(5000)); // incoming-window
            list.Add(new AMQPSmallUInt((byte)nextOutgoingId)); // next-outgoing-id
            list.Add(new AMQPUInt(5000)); // outgoing-window
            list.Add(new AMQPSmallUInt((byte)handle)); // handle
            list.Add(new AMQPSmallUInt(0)); // delivery-count
            list.Add(new AMQPUInt((uint)linkCredit)); // link-credit
            list.Add(new AMQPSmallUInt(0)); // available
            list.Add(new AMQPNull()); // Drain
            list.Add(new AMQPFalse()); // Echo
            list.Add(new AMQPNull()); // Properties

            base.Init(AMQPMessageType.AMQPFlow, list);
        }
    }

    public class AMQPAttach : AMQPMessage
    {
        public AMQPAttach(string linkName, string serviceBus, string SAS, string trackingId, bool isInput, int handle)
        {
            // Define some variables
            AMQPConstructor source;
            AMQPConstructor target;
            AMQPItem direction;
            if (isInput)
            {
                direction = new AMQPTrue();
                
                AMQPList sList = new AMQPList();
                sList.Add(new AMQPString(serviceBus)); // Source name
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                source = new AMQPConstructor(new AMQPSmallULong(0x28),sList);

                AMQPList tList = new AMQPList();
                tList.Add(new AMQPNull()); // Target name
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                target = new AMQPConstructor(new AMQPSmallULong(0x29), tList);
            }
            else
            {
                direction = new AMQPFalse();

                AMQPList sList = new AMQPList();
                sList.Add(new AMQPNull()); // Source name
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                sList.Add(new AMQPNull()); // 
                source = new AMQPConstructor(new AMQPSmallULong(0x28), sList);

                AMQPList tList = new AMQPList();
                tList.Add(new AMQPString(serviceBus)); // Target name
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                tList.Add(new AMQPNull()); // 
                target = new AMQPConstructor(new AMQPSmallULong(0x29), tList);
            }

            AMQPMap properties = new AMQPMap();
            properties.Add(new AMQPSymbol("com.microsoft:swt"), new AMQPString(SAS));
            properties.Add(new AMQPSymbol("com.microsoft:client-agent"), new AMQPString("ServiceBus/3.0.51093.14;"));
            properties.Add(new AMQPSymbol("com.microsoft:dynamic-relay"), new AMQPFalse());
            properties.Add(new AMQPSymbol("com.microsoft:listener-type"), new AMQPString("RelayedConnection"));
            properties.Add(new AMQPSymbol("com.microsoft:tracking-id"), new AMQPString(trackingId));

            // Ref: http://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html#type-attach
            AMQPList list = new AMQPList();
            list.Add(new AMQPString(linkName)); // Link name
            list.Add(new AMQPSmallUInt((byte)handle));
            list.Add(direction); // Direction 
            list.Add(new AMQPNull()); // snd-settle-mode
            list.Add(new AMQPNull()); // rcv-settle-mode
            list.Add(source); // source
            list.Add(target); // target
            list.Add(new AMQPNull()); // unsettled
            list.Add(new AMQPNull()); // incomplete-unsettled
            list.Add(new AMQPNull()); // initial-delivery-count
            list.Add(new AMQPNull()); // max-message-size
            list.Add(new AMQPNull()); // offered-capabilities
            list.Add(new AMQPNull()); // desired-capabilities
            list.Add(properties); // properties

            base.Init(AMQPMessageType.AMQPAttach, list);
        }
    }

    public class AMQPOpen : AMQPMessage
    {
        public AMQPOpen(string containerId, string hostName)
        {
            AMQPList list = new AMQPList();
            list.Add(new AMQPString(containerId));
            list.Add(new AMQPString(hostName));
            list.Add(new AMQPUInt(65536)); // Max Frame Size
            list.Add(new AMQPUShort(8191)); // Channel max
            list.Add(new AMQPNull()); // Idle timeout in milliseconds.
            list.Add(new AMQPNull()); // Outgoing locales
            list.Add(new AMQPNull()); // Incoming locales
            list.Add(new AMQPNull()); // Offered capabilities
            list.Add(new AMQPNull()); // Desired capabilities
            list.Add(new AMQPNull()); // Properties

            base.Init(AMQPMessageType.AMQPOpen, list);
        }
    }

    

    public class AMQPBegin : AMQPMessage
    {
        public AMQPBegin()
        {
            AMQPList list = new AMQPList();
            list.Add(new AMQPNull()); // Remote channel
            list.Add(new AMQPSmallUInt(1)); // Next outgoing id
            list.Add(new AMQPUInt(5000)); // Incoming window
            list.Add(new AMQPUInt(5000)); // Outgoing window
            list.Add(new AMQPUInt(262143)); // Handle max
            list.Add(new AMQPNull()); // Offered capabilities
            list.Add(new AMQPNull()); // Desired capabilities
            list.Add(new AMQPNull()); // Properties

            base.Init(AMQPMessageType.AMQPBegin, list);
        }
    }

    public class AMQPProtocolHeader : AMQPItem
    {
        public AMQPProtocolHeader(AMQPProtocol type, int major = 1, int minor = 0, int revision = 0)
        {
            base.WriteByteArray(new byte[] { 0x41, 0x4D, 0X51, 0X50 }); // AMQP
            base.WriteByte((byte)type);
            base.WriteByte((byte)major);
            base.WriteByte((byte)minor);
            base.WriteByte((byte)revision);
        }
    }

    public class AMQPMessage : AMQPItem
    {
        
        public void Init(AMQPMessageType type, AMQPItem content)
        {
            int messageType = 0; // AMQP
            if (type == AMQPMessageType.SASLInit)
                messageType = 1; // SASL

            byte[] binContent = content.ToByteArray();

            // Write the header
            base.WriteInt32(binContent.Length + 11); // Size of the message
            base.WriteByte(0x02); // DOFF = 2
            base.WriteByte((byte)messageType);
            base.WriteByte(0x00);
            base.WriteByte(0x00);
            base.WriteByte(0x00);
            base.WriteByteArray(new AMQPSmallULong((byte)type).ToByteArray());

            // Write the content
            base.WriteByteArray(content.ToByteArray());
        }

    }
    public abstract class AMQPItem
    {
        private MemoryStream stream;

        // Write given item to buffer. If not created, create one.
        private void Write(byte[] bytes)
        {
            if (this.stream == null)
                this.stream = new MemoryStream();

            WriteToStream(this.stream, bytes);
            
        }

        public void WriteToStream(MemoryStream stream, byte[] bytes)
        {
            stream.Write(bytes, 0, bytes.Length);
        }

        protected void ClearBuffer()
        {
            if (this.stream != null)
            {
                this.stream.Dispose();
                this.stream = null;
            }
        }

        protected void WriteByte(byte value)
        {
            Write(new byte[] { value });
        }
        protected void WriteByteArray(byte[] item)
        {
            Write((byte[])item);
        }

        protected void WriteInt16(Int16 value)
        {
            WriteInteger((Int16)value);
        }

        protected void WriteUInt16(UInt16 value)
        {
            WriteInteger((UInt16)value);
        }

        protected void WriteUInt32(UInt32 value)
        {
            WriteInteger((UInt32)value);
        }
        protected void WriteInt32(Int32 value)
        {
            WriteInteger((Int32)value);
        }

        protected void WriteUInt64(UInt64 value)
        {
            WriteInteger((UInt64)value);
        }
        protected void WriteInt64(Int64 value)
        {
            WriteInteger((Int64)value);
        }

        private void WriteInteger(Object value)
        {
            byte[] binValue = null;

            switch (value)
            {
                case UInt16 _:
                    binValue = BitConverter.GetBytes((UInt16)value);
                    break;
                case Int16 _:
                    binValue = BitConverter.GetBytes((Int16)value);
                    break;
                case UInt32 _:
                    binValue = BitConverter.GetBytes((UInt32)value);
                    break;
                case Int32 _:
                    binValue = BitConverter.GetBytes((Int32)value);
                    break;
                case UInt64 _:
                    binValue = BitConverter.GetBytes((UInt64)value);
                    break;
                case Int64 _:
                    binValue = BitConverter.GetBytes((Int64)value);
                    break;
            }
            if (binValue != null)
            {
                Array.Reverse(binValue);
                WriteByteArray(binValue);
            }

        }

        // Return the content of the buffer and dispose it.
        protected byte[] GetBytes()
        {
            byte[] retVal = null;
            if (this.stream != null)
            {
                retVal = this.stream.ToArray();
            }
            return retVal;
        }
        virtual public byte[] ToByteArray()
        {
            return GetBytes();
        }
    }

    public class AMQPConstructor : AMQPItem
    {
        public AMQPConstructor(AMQPItem descriptor, AMQPItem value)
        {
            base.WriteByte(0x00); // Constructor
            base.WriteByteArray(descriptor.ToByteArray());
            base.WriteByteArray(value.ToByteArray());
        }
    }

    public class AMQPNull : AMQPItem
    {
        override public byte[] ToByteArray()
        {
            return new byte[] { 0x40 };
        }
    }

    

    public class AMQPTrue : AMQPItem
    {
        override public byte[] ToByteArray()
        {
            return new byte[] { 0x41 };
        }
    }

    public class AMQPFalse : AMQPItem
    {
        override public byte[] ToByteArray()
        {
            return new byte[] { 0x42 };
        }
    }

    public class AMQPZero : AMQPItem
    {
        override public byte[] ToByteArray()
        {
            return new byte[] { 0x43 };
        }
    }
    public class AMQPBoolean : AMQPItem
    {
        public AMQPBoolean(bool boolean)
        {
            base.WriteByte(0x56); // Boolean
            if (boolean)
                base.WriteByte(0x01);
            else
                base.WriteByte(0x00);
        }
    }

    public class AMQPUByte : AMQPItem
    {
        public AMQPUByte(byte value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x50); // UByte
                base.WriteByte(value);
            }
        }
    }

    public class AMQPByte : AMQPItem
    {
        public AMQPByte(byte value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x51); // Byte
                base.WriteByte(value);
            }
        }
    }

    public class AMQPSmallUInt : AMQPItem
    {
        public AMQPSmallUInt(byte value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x52); // SmallUInt
                base.WriteByte(value);
            }
        }
    }

    public class AMQPSmallULong : AMQPItem
    {
        public AMQPSmallULong(byte value)
        {
            if (value == 0)
                base.WriteByte(0x44); // Zero
            else
            {
                base.WriteByte(0x53); // SmallULong
                base.WriteByte(value);
            }
        }
    }

    public class AMQPSmallInt : AMQPItem
    {
        public AMQPSmallInt(byte value)
        {
            base.WriteByte(0x54); // SmallInt
            base.WriteByte(value);
        }
    }

    public class AMQPSmallLong : AMQPItem
    {
        public AMQPSmallLong(byte value)
        {
            base.WriteByte(0x55); // SmallLong
            base.WriteByte(value);
        }
    }
    public class AMQPUShort : AMQPItem
    {
        public AMQPUShort(UInt16 value)
        {
            base.WriteByte(0x60); // UShort
            base.WriteUInt16(value);
        }
    }

    public class AMQPShort : AMQPItem
    {
        public AMQPShort(Int16 value)
        {
            base.WriteByte(0x61); // Short
            base.WriteInt16(value);
        }
    }

    public class AMQPUInt : AMQPItem
    {
        public AMQPUInt(UInt32 value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x70); // UInt
                base.WriteUInt32(value);
            }
        }
    }

    public class AMQPInt : AMQPItem
    {
        public AMQPInt(Int32 value)
        {
            base.WriteByte(0x71); // Int
            base.WriteInt32(value);
        }
    }


    public class AMQPFloat : AMQPItem
    {
        [Obsolete("This AMQP item is not tested!")]
        public AMQPFloat(Int32 value)
        {
            base.WriteByte(0x72); // Float
            base.WriteInt32(value);
        }
    }

    public class AMQPChar : AMQPItem
    {
        [Obsolete("This AMQP item is not tested!")]
        public AMQPChar(char highSurrogate, char lowSurrogate)
        {
            base.WriteByte(0x73); // Char
            int utf32 = Char.ConvertToUtf32(highSurrogate, lowSurrogate);
            base.WriteInt32(utf32);
        }
    }

    public class AMQPDecimal32 : AMQPItem
    {
        [Obsolete("This AMQP item is not tested!")]
        public AMQPDecimal32()
        {
            base.WriteByte(0x74); // Decimal32
            base.WriteInt32(0);
        }
    }

    public class AMQPULong : AMQPItem
    {
        public AMQPULong(UInt64 value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x80); // ULong
                base.WriteUInt64(value);
            }
        }
    }

    public class AMQPLong : AMQPItem
    {
        public AMQPLong(Int64 value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x81); // Long
                base.WriteInt64(value);
            }
        }
    }

    public class AMQPDouble : AMQPItem
    {
        public AMQPDouble(Double value)
        {
            if (value == 0)
                base.WriteByte(0x43); // Zero
            else
            {
                base.WriteByte(0x82); // Double
                byte[] binDouble = BitConverter.GetBytes((double)value);
                Array.Reverse(binDouble);
                base.WriteByteArray(binDouble);
            }
        }
    }

    public class AMQPTimeStamp : AMQPItem
    {
        public AMQPTimeStamp(DateTime timeStamp)
        {
            base.WriteByte(0x83); // Timestamp

            UInt32 seconds = (UInt32)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            base.WriteUInt32(seconds);
        }
    }

    public class AMQPDecimal64 : AMQPItem
    {
        [Obsolete("This AMQP item is not tested!")]
        public AMQPDecimal64()
        {
            base.WriteByte(0x84); // Decimal64
            base.WriteInt64(0);
        }
    }

    public class AMQPDecimal128 : AMQPItem
    {
        [Obsolete("This AMQP item is not tested!")]
        public AMQPDecimal128()
        {
            base.WriteByte(0x94); // Decimal128
            base.WriteInt64(0);
            base.WriteInt64(0);
        }
    }

    public class AMQPUUID : AMQPItem
    {
        public AMQPUUID(Guid guid)
        {
            base.WriteByte(0x98); // Guid
            byte[] binGuid = guid.ToByteArray();
            Array.Reverse(binGuid);
            base.WriteByteArray(binGuid);
        }
    }

    public class AMQPBinary : AMQPItem
    {
        public AMQPBinary(byte[] content)
        {
            if (content.Length < 255)
            {
                base.WriteByte(0xA0); // Binary, one size byte
                base.WriteByte((byte)content.Length);
            }
            else
            {
                base.WriteByte(0xB0); // Binary, four size bytes
                base.WriteUInt32((UInt32)content.Length);
            }
            base.WriteByteArray(content);
        }
    }

    public class AMQPString : AMQPItem
    {
        public AMQPString(string content)
        {
            byte[] binContent = System.Text.Encoding.UTF8.GetBytes(content);
            if (binContent.Length < 255)
            {
                base.WriteByte(0xA1); // String, one size byte
                base.WriteByte((byte)binContent.Length);
            }
            else
            {
                base.WriteByte(0xB1); // String, four size bytes
                base.WriteUInt32((UInt32)binContent.Length);
            }
            base.WriteByteArray(binContent);
        }
    }


    public class AMQPSymbol : AMQPItem
    {
        public AMQPSymbol(string content)
        {
            byte[] binContent = System.Text.Encoding.ASCII.GetBytes(content);
            if (binContent.Length < 255)
            {
                base.WriteByte(0xA3); // Symbol, one size byte
                base.WriteByte((byte)binContent.Length);
            }
            else
            {
                base.WriteByte(0xB3); // Symbol, four size bytes
                base.WriteUInt32((UInt32)binContent.Length);
            }
            base.WriteByteArray(binContent);
        }
    }

    public class AMQPList : AMQPItem
    {
        private List<AMQPItem> items;
        public AMQPList()
        {
            this.items = new List<AMQPItem>();
        }
        public void Add(AMQPItem item)
        {
            this.items.Add(item);
        }
        override public byte[] ToByteArray()
        {
            if (items.Count == 0)
            {
                base.WriteByte(0x45); // Empty list
            }
            else
            {
                // First, write all elements to a byte array
                MemoryStream m = new MemoryStream();

                IEnumerator e = this.items.GetEnumerator();
                while (e.MoveNext())
                {
                    byte[] binItem = ((AMQPItem)e.Current).ToByteArray();
                    m.Write(binItem,0,binItem.Length);
                }
                byte[] binElements = m.ToArray();
                m.Dispose();

                // Clear the current buffer
                base.ClearBuffer();

                // Construct the header
                if (items.Count < 255 && binElements.Length < 255)
                {
                    base.WriteByte(0xC0); // List, one byte size and length
                    base.WriteByte((byte)(binElements.Length+1)); // Length of the list in bytes
                    base.WriteByte((byte)items.Count); // Number of elements of the list
                }
                else
                {
                    base.WriteByte(0xD0); // List, four byte size and length
                    base.WriteUInt32((uint)(binElements.Length+4)); // Length of the list in bytes
                    base.WriteUInt32((uint)items.Count); // Number of elements of the list
                }

                // Add the content
                base.WriteByteArray(binElements);
            }

            return GetBytes();
        }
    }

    public class AMQPArray : AMQPItem
    {
        private List<AMQPItem> items;
        public AMQPArray()
        {
            this.items = new List<AMQPItem>();
        }
        public void Add(AMQPItem item)
        {
            // Check the type, must same unless null
            if(items.Count > 0 && items.ElementAt(0).GetType() != item.GetType())
                throw new InvalidCastException("Elements of an array must be of same type!");
            
            this.items.Add(item);
        }
        override public byte[] ToByteArray()
        {
            if (items.Count == 0)
                throw new NullReferenceException("Array can't be empty!");

            byte type = 0;
            // First, write all elements to a byte array WITHOUT type
            MemoryStream m = new MemoryStream();

            IEnumerator e = this.items.GetEnumerator();

            while (e.MoveNext())
            {
                // Get the binary form of item and extract type
                byte[] binItem = ((AMQPItem)e.Current).ToByteArray();
                type = binItem[0];
                // Write item without type
                m.Write(binItem, 1, binItem.Length-1);
            }
            byte[] binElements = m.ToArray();
            m.Dispose();

            // Clear the current buffer
            base.ClearBuffer();

            // Construct the header
            if (items.Count < 256 && binElements.Length < 255)
            {
                base.WriteByte(0xE0); // Array, one byte size and length
                base.WriteByte((byte)(binElements.Length+1)); // Lenght of the list in bytes
                base.WriteByte((byte)items.Count); // Number of elements of the list
            }
            else
            {
                base.WriteByte(0xF0); // Array, four byte size and length
                base.WriteUInt32((uint)binElements.Length+4); // Lenght of the list in bytes
                base.WriteUInt32((uint)items.Count); // Number of elements of the list
            }

            // Write the type
            base.WriteByte(type);
            // Add the content
            base.WriteByteArray(binElements);

            return GetBytes();
        }
    }
    public class AMQPMap : AMQPItem
    {
        private List<AMQPItem> keys;
        private List<AMQPItem> values;
        public AMQPMap()
        {
            this.keys = new List<AMQPItem>();
            this.values = new List<AMQPItem>();
        }
        public void Add(AMQPItem key, AMQPItem value)
        {
            this.keys.Add(key);
            this.values.Add(value);
        }
        override public byte[] ToByteArray()
        {
            if (keys.Count == 0)
                throw new NullReferenceException("Map can't be empty!");

            // First, write all elements to a byte array
            MemoryStream m = new MemoryStream();

            for(int a = 0; a < this.keys.Count; a++)
            {
                // Write the key
                byte[] binItem = this.keys.ElementAt(a).ToByteArray();
                m.Write(binItem, 0, binItem.Length);

                // Write the value
                binItem = this.values.ElementAt(a).ToByteArray();
                m.Write(binItem, 0, binItem.Length);
            }
            byte[] binElements = m.ToArray();
            m.Dispose();

            // Clear the current buffer
            base.ClearBuffer();

            // Construct the header
            if (keys.Count*2 < 255 && binElements.Length < 255)
            {
                base.WriteByte(0xC1); // Map, one byte size and length
                base.WriteByte((byte)(binElements.Length+2)); // Lenght of the list in bytes
                base.WriteByte((byte)(keys.Count * 2)); // Number of elements of the map (incl. keys & values)
            }
            else
            {
                base.WriteByte(0xD1); // List, four byte size and length
                base.WriteUInt32((uint)binElements.Length + 5); // Lenght of the list in bytes
                base.WriteUInt32((uint)keys.Count * 2); // Number of elements of the map (incl. keys & values)
            }

            // Add the content
            base.WriteByteArray(binElements);

            return GetBytes();
        }
    }
}
