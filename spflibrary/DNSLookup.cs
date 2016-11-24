using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using DNS.Client;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace spflibrary
{
	public static class DNSLookup
	{
		private static string defaultDnsServerIp = "8.8.8.8";
		private static string dnsServerIp = defaultDnsServerIp;
		private static DnsClient client = null;

		private static DnsClient GetClient()
		{
			if(client == null)
			{
				client = new DnsClient(dnsServerIp);
			}
			return client;
		}

		public static bool DoesDomainExist(string domain)
		{
			//This is good enough for SPF spec, but is not good enough in other applications
			return LookupARecords(domain).Count > 0;
		}

		public static bool IsValidDomain(string domain)
		{
			return Uri.CheckHostName(domain) != UriHostNameType.Unknown;
		}

		public static List<string> LookupARecords(string domain)
		{
			if (!IsValidDomain(domain))
			{
				throw new ArgumentException("Illegal domain name given");
			}

			ClientRequest request = GetClient().Create();

			Question q = new Question(new Domain(domain), RecordType.A);
			request.RecursionDesired = true;
			request.Questions.Add(q);

			try
			{
				ClientResponse cr = request.Resolve();

				IList<IPAddress> ips = cr.AnswerRecords
				.Where(r => r.Type == RecordType.A)
				.Cast<IPAddressResourceRecord>()
				.Select(r => r.IPAddress)
				.ToList();

				if (ips.Count < 1)
				{
					return null;
				}

				return ips.Select(i => i.ToString()).ToList();
			}
			catch (ResponseException)
			{
				return null;
			}
		}

		public static List<string> LookupARecords(IEnumerable<string> domains)
		{
			if(domains == null)
			{
				return null;
			}

			List<string> ips = new List<string>();
			foreach (string domain in domains)
			{
				ips.AddRange(LookupARecords(domain));
			}
			return ips;
		}

		public static List<string> LookupMXRecords(string domain)
		{
			if (!IsValidDomain(domain))
			{
				throw new ArgumentException("Illegal domain name given");
			}

			ClientRequest request = GetClient().Create();

			Question q = new Question(new Domain(domain), RecordType.MX);
			request.RecursionDesired = true;
			request.Questions.Add(q);

			try
			{
				ClientResponse cr = request.Resolve();

				//Only hosts can be the target of MX records
				IList<string> domainsRes = cr.AnswerRecords
				.Where(r => r.Type == RecordType.MX)
				.Cast<MailExchangeResourceRecord>()
				.Select(r => r.ExchangeDomainName.ToString())
				.ToList();

				if (domainsRes.Count < 1)
				{
					return null;
				}

				return domainsRes.ToList();
			}
			catch (ResponseException)
			{
				return null;
			}
		}

		public static List<string> LookupPTRRecords(string ip)
		{
			if (!IPTool.ValidIPAddress(ip))
			{
				throw new ArgumentException("Illegal ip given");
			}

			IPAddress ipAddress = IPAddress.Parse(ip);
			ClientRequest request = GetClient().Create();

			Question q = new Question(Domain.PointerName(ipAddress), RecordType.PTR);
			request.RecursionDesired = true;
			request.Questions.Add(q);

			try
			{
				ClientResponse cr = request.Resolve();

				IList<string> ips = cr.AnswerRecords
				.Where(r => r.Type == RecordType.PTR)
				.Cast<PointerResourceRecord>()
				.Select(r => r.PointerDomainName.ToString())
				.ToList();

				if (ips.Count < 1)
				{
					return null;
				}

				return ips.ToList();
			}
			catch (ResponseException e)
			{
				return null;
			}
			throw new NotImplementedException();
		}

		public static List<string> LookupSPFRecords(string domain)
		{
			if (!IsValidDomain(domain))
			{
				throw new ArgumentException("Illegal domain name given");
			}

			ClientRequest request = GetClient().Create();

			Question q = new Question(new Domain(domain), RecordType.TXT);
			request.RecursionDesired = true;
			request.Questions.Add(q);

			try
			{
				ClientResponse cr = request.Resolve();

				IList<string> txtRecs = cr.AnswerRecords
				.Where(r => r.Type == RecordType.TXT)
				.Cast<ResourceRecord>()
				.Select(r => Encoding.UTF8.GetString(r.Data))
				.ToList();

				//The UTF8 conversion is bringing back some garbage at the start, clean that up
				for (int i = 0; i < txtRecs.Count; i++)
				{
					int index = txtRecs[i].IndexOf("v=spf");
					if(index != -1)
					{
						txtRecs[i] = txtRecs[i].Substring(index);
					}
					else
					{
						txtRecs.RemoveAt(i--);
					}
				}

				if (txtRecs.Count < 1)
				{
					return null;
				}

				return txtRecs.ToList();
			}
			catch (ResponseException)
			{
				return null;
			}
		}

		public static void SetDNSServer(string serverIp)
		{
			IPAddress address;
			if(!IPAddress.TryParse(serverIp, out address))
			{
				throw new ArgumentException("Invalid dns server ip");
			}
			 
			client = null;
			dnsServerIp = serverIp;

			client = new DnsClient(dnsServerIp);
		}
	}
}
