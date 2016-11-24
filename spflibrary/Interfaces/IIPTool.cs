
namespace spflibrary.interfaces
{
	interface IIPTool
	{
		bool ValidIPAddress(string ip);

		bool ValidIPv4Address(string ip);

		bool ValidIPv6Address(string ip);

		bool ContainsIPv4(string ip, string cidr);

		bool ContainsIPv6(string ip, string cidr);
	}
}
