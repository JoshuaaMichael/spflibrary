using System;
using System.Net;
using System.Net.Sockets;

namespace spflibrary
{
	public static class IPTool
	{
		public static bool ValidIPAddress(string ip)
		{
			return (ValidIPv4Address(ip) || ValidIPv6Address(ip));
		}

		public static bool ValidIPv4Address(string ip)
		{
			IPAddress address;
			if (IPAddress.TryParse(ip, out address))
			{
				return (address.AddressFamily == AddressFamily.InterNetwork);
			}
			return false;
		}

		public static bool ValidIPv4CIDR(string cidr)
		{
			try
			{
				IPNetwork ipCidr = IPNetwork.Parse(cidr);
				return (ipCidr.AddressFamily == AddressFamily.InterNetwork);
			}
			catch(ArgumentException)
			{
				return false;
			}
		}

		public static bool ValidIPv6Address(string ip)
		{
			IPAddress address;
			if (IPAddress.TryParse(ip, out address))
			{
				return (address.AddressFamily == AddressFamily.InterNetworkV6);
			}
			return false;
		}

		public static bool ValidIPv6CIDR(string cidr)
		{
			try
			{
				IPNetwork ipCidr = IPNetwork.Parse(cidr);
				return (ipCidr.AddressFamily == AddressFamily.InterNetworkV6);
			}
			catch (ArgumentException)
			{
				return false;
			}
		}

		public static bool ContainsIPv4(string ip, string cidr)
		{
			if(!ValidIPv4Address(ip))
			{
				throw new ArgumentException("Illegal IP address");
			}

			if (!ValidIPv4CIDR(cidr))
			{
				throw new ArgumentException("Illegal IP address cidr");
			}

			IPAddress ipAddress = IPAddress.Parse(ip);
			IPNetwork ipCidr = IPNetwork.Parse(cidr);

			return IPNetwork.Contains(ipCidr, ipAddress);
		}

		public static bool ContainsIPv6(string ip, string cidr)
		{
			if (!ValidIPv6Address(ip))
			{
				throw new ArgumentException("Illegal IP address");
			}

			if (!ValidIPv6CIDR(cidr))
			{
				throw new ArgumentException("Illegal IP address cidr");
			}

			IPAddress ipAddress = IPAddress.Parse(ip);
			IPNetwork ipCidr = IPNetwork.Parse(cidr);

			return IPNetwork.Contains(ipCidr, ipAddress);
		}

		public static bool ContainsIP(string ip, string cidr)
		{
			if (ValidIPv4Address(ip) && ValidIPv4CIDR(cidr))
			{
				return ContainsIPv4(ip, cidr);
			}

			if (ValidIPv6Address(ip) && ValidIPv6CIDR(cidr))
			{
				return ContainsIPv6(ip, cidr);
			}

			throw new ArgumentException("Illegal ip address or cidr given");
		}

		public static bool IsSameIP(string ip1, string ip2)
		{
			if((ValidIPv4Address(ip1) && ValidIPv4Address(ip2)) || (ValidIPv6Address(ip1) && ValidIPv6Address(ip2)))
			{
				//Both ips are valid and of the same ip version
				IPAddress ipAddress1 = IPAddress.Parse(ip1);
				IPAddress ipAddress2 = IPAddress.Parse(ip2);
				return (ipAddress1.ToString() == ipAddress2.ToString()); //Could've compared byte arrays
			}
			return false;
		}
	}
}
