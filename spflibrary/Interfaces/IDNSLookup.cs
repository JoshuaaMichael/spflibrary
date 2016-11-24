using System.Collections.Generic;

namespace spflibrary.interfaces
{
	interface IDNSLookup
	{
		void SetDNSServer(string dnsServerIP);

		bool IsValidDomain(string domain);

		bool DoesDomainExist(string domain);

		List<string> LookupSPFRecord(string domain);

		List<string> LookupARecord(string domain);

		List<string> LookupMXRecord(string domain);

		List<string> LookupPTRRecord(string domain);
	}
}
