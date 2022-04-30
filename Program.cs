using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Polly;
using Polly.Extensions.Http;

namespace ddns_pushover;

class Program
{
    static async Task<int> Main(string[] args)
    {




        var cfTokenOption = new Option<string>(
            aliases: new[] { "-t", "--token" },
            description: "Cloudflare authentication token.")
        { IsRequired = true };

        var cfZoneOption = new Option<string>(
            aliases: new[] { "-z", "--zone" },
            description: "Cloudflare zone.")
        { IsRequired = true };

        var dnsIpv4RecordsOption = new Option<string[]>(
            aliases: new[] { "-4", "--ipv4" },
            description: "DNS A record id to update."
        );

        var dnsIpv6RecordsOption = new Option<string[]>(
            aliases: new[] { "-6", "--ipv6" },
            description: "DNS AAAA record id to update."
        );

        var pushoverToken = new Option<string>(
            aliases: new[] { "-p", "--pushover-token" },
            description: "PushOver Token."
        );

        var pushoverUser = new Option<string>(
            aliases: new[] { "-u", "--pushover-user" },
            description: "PushOver user."
        );

        var pushoverDevices = new Option<string[]>(
            aliases: new[] { "-d", "--device" },
            description: "PushOver device(s)."
        );


        var rootCommand = new RootCommand("Dynamic DNS for cloudflare.");
        rootCommand.AddOption(cfTokenOption);
        rootCommand.AddOption(cfZoneOption);
        rootCommand.AddOption(dnsIpv4RecordsOption);
        rootCommand.AddOption(dnsIpv6RecordsOption);
        rootCommand.AddOption(pushoverToken);
        rootCommand.AddOption(pushoverUser);
        rootCommand.AddOption(pushoverDevices);
        rootCommand.AddValidator(result =>
        {
            if (result.GetValueForOption(dnsIpv4RecordsOption)?.Length + result.GetValueForOption(dnsIpv6RecordsOption)?.Length < 1)
            {
                result.ErrorMessage = "At least ONE A or AAAA record is required.";
            }
        });
        rootCommand.SetHandler(async (string token, string zone, string[] ipv4Ids, CancellationToken cancellationToken) =>
        {

            IHost host = Host.CreateDefaultBuilder(args)
            .ConfigureServices((ctx, services) =>
            {
                services.AddHttpClient("ipv4client")
                    .SetHandlerLifetime(TimeSpan.FromMinutes(1))
                    .AddPolicyHandler(HttpPolicyExtensions
                        .HandleTransientHttpError()
                        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.NotFound)
                        .WaitAndRetryAsync(6, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt))));
            })
            .Build();
            await host.StartAsync(cancellationToken);

            System.Console.WriteLine(token);
            System.Console.WriteLine(zone);
            foreach (var i in ipv4Ids)
            {
                System.Console.WriteLine(i);
            }
            await GetMyIPv4();

            await host.StopAsync(cancellationToken);
        },
            cfTokenOption, cfZoneOption, dnsIpv4RecordsOption
        );

        return await rootCommand.InvokeAsync(args);



        // var dohclient = new HttpClient();
        // var req = new HttpRequestMessage(HttpMethod.Get, "https://1.0.0.1/dns-query?name=www.cloudflare.com");
        // req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-json"));
        // var resp = await dohclient.SendAsync(req);
        // var stream = await resp.Content.ReadAsStreamAsync();
        // var dnsresult = await JsonSerializer.DeserializeAsync<DNSQueryResult>(stream);
        // foreach (var r in dnsresult?.Answer)
        // {
        //     System.Console.WriteLine(r.Data);
        // }


    }



    static async Task<string> GetMyIPv4()
    {
        var client = new HttpClient(new SocketsHttpHandler()
        {
            ConnectCallback = async (ctx, cancellationToken) =>
            {
                var entry = await Dns.GetHostEntryAsync(ctx.DnsEndPoint.Host, AddressFamily.InterNetwork, cancellationToken);

                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                socket.NoDelay = true;
                try
                {
                    await socket.ConnectAsync(entry.AddressList, ctx.DnsEndPoint.Port, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
            UseProxy = false
        });
        var result = await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
        //System.Console.WriteLine(result);
        string myip = string.Empty;

        foreach (var line in result.Split('\n'))
        {
            var segs = line.Split('=');
            if (segs[0] == "ip")
            {
                myip = segs[1];
            }
        }

        client.Dispose();

        System.Console.WriteLine($"myip: {myip}");
        return myip;
    }

    static async Task<string> UpdateDNS(string token, string zone, string ipv4Ids, string ipv6Ids)
    {
        throw new NotImplementedException();
    }


    public class DNSQueryResult
    {
        public int Status { get; set; } = 0;
        public bool TC { get; set; }
        public bool RD { get; set; }
        public bool RA { get; set; }
        public bool AD { get; set; }
        public bool CD { get; set; }
        public DNSQuestion[] Question { get; set; } = { };
        public DNSAnswer[] Answer { get; set; } = { };


        public class DNSQuestion
        {
            [JsonPropertyName("name")]
            public string Name { get; set; } = "";
            [JsonPropertyName("type")]
            public int Type { get; set; }
        }
        public class DNSAnswer
        {
            [JsonPropertyName("name")]
            public string Name { get; set; } = "";

            [JsonPropertyName("type")]
            public int Type { get; set; }
            public int TTL { get; set; }

            [JsonPropertyName("data")]
            public string Data { get; set; } = "";
        }
    }
}
