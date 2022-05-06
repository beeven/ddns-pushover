using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
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

        var pushoverTokenOption = new Option<string>(
            aliases: new[] { "-p", "--pushover-token" },
            description: "PushOver Token."
        );

        var pushoverUserOption = new Option<string>(
            aliases: new[] { "-u", "--pushover-user" },
            description: "PushOver user."
        );

        var pushoverDevicesOption = new Option<string[]>(
            aliases: new[] { "-d", "--device" },
            description: "PushOver device(s)."
        );


        var rootCommand = new RootCommand("Dynamic DNS for cloudflare.");
        rootCommand.AddOption(cfTokenOption);
        rootCommand.AddOption(cfZoneOption);
        rootCommand.AddOption(dnsIpv4RecordsOption);
        rootCommand.AddOption(dnsIpv6RecordsOption);
        rootCommand.AddOption(pushoverTokenOption);
        rootCommand.AddOption(pushoverUserOption);
        rootCommand.AddOption(pushoverDevicesOption);
        rootCommand.AddValidator(result =>
        {
            if (result.GetValueForOption(dnsIpv4RecordsOption)?.Length + result.GetValueForOption(dnsIpv6RecordsOption)?.Length < 1)
            {
                result.ErrorMessage = "At least ONE A or AAAA record is required.";
            }
        });
        rootCommand.SetHandler(async (string token, string zone, string[] ipv4Ids, string[] ipv6Ids, string pushoverToken, string pushoverUser, string[] pushoverDevices, CancellationToken cancellationToken) =>
        {

            IHost host = Host.CreateDefaultBuilder(args)
            .ConfigureServices((ctx, services) =>
            {
                services.AddHttpClient("ipv4client")
                    .ConfigurePrimaryHttpMessageHandler(() =>
                        new SocketsHttpHandler()
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
                            UseProxy = false,
                        })
                    .SetHandlerLifetime(TimeSpan.FromMinutes(5))
                    .AddPolicyHandler(HttpPolicyExtensions
                        .HandleTransientHttpError()
                        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.NotFound)
                        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt))));

                services.AddHttpClient("ipv6client")
                    .ConfigurePrimaryHttpMessageHandler(() =>
                        new SocketsHttpHandler()
                        {
                            ConnectCallback = async (ctx, cancellationToken) =>
                            {
                                var entry = await Dns.GetHostEntryAsync(ctx.DnsEndPoint.Host, AddressFamily.InterNetworkV6, cancellationToken);
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
                            UseProxy = false,
                        })
                    .SetHandlerLifetime(TimeSpan.FromMinutes(5))
                    .AddPolicyHandler(HttpPolicyExtensions
                        .HandleTransientHttpError()
                        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.NotFound)
                        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt))));

                services.AddHttpClient("apiclient")
                    .AddPolicyHandler(
                        HttpPolicyExtensions
                        .HandleTransientHttpError()
                        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.NotFound)
                        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)))
                    );
            })
            .Build();
            await host.StartAsync(cancellationToken);


            var ip4 = await GetMyIP(host.Services, ipv6: false, cancellationToken);
            System.Console.WriteLine($"my ipv4: {ip4}");
            var ip6 = await GetMyIP(host.Services, ipv6: true, cancellationToken);
            System.Console.WriteLine($"my ipv6: {ip6}");

            var ips = await UpdateDNS(token, zone, ip4, ipv4Ids, ip6, ipv6Ids, host.Services, cancellationToken);

            if(ips.Except(new[]{ip4, ip6}).Count()>0 && !string.IsNullOrEmpty(pushoverToken) && !string.IsNullOrEmpty(pushoverUser))
            {
                await Notify(pushoverToken, pushoverUser, pushoverDevices, ip4, ip6, ips, host.Services, cancellationToken);
            }


            await host.StopAsync(cancellationToken);
        },
            cfTokenOption, cfZoneOption, dnsIpv4RecordsOption, dnsIpv6RecordsOption, pushoverTokenOption, pushoverUserOption, pushoverDevicesOption
        );

        return await rootCommand.InvokeAsync(args);

    }

    static async Task<string> GetMyIP(IServiceProvider services, bool ipv6, CancellationToken cancellationToken)
    {
        var clientFactory = services.GetRequiredService<IHttpClientFactory>();
        HttpClient client;
        if (ipv6)
        {
            client = clientFactory.CreateClient("ipv6client");
        }
        else
        {
            client = clientFactory.CreateClient("ipv4client");
        }
        try
        {
            var result = await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace", cancellationToken);
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
            return myip;
        }
        catch (HttpRequestException ex)
        {
            System.Console.WriteLine(ex.Message);
            return "";
        }
    }



    static async Task<string[]> UpdateDNS(string token, string zone, string ip4, string[] ipv4Ids, string ip6, string[] ipv6Ids, IServiceProvider services, CancellationToken cancellationToken)
    {
        var clientFactory = services.GetRequiredService<IHttpClientFactory>();
        var client = clientFactory.CreateClient("apiclient");
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        client.BaseAddress = new Uri("https://api.cloudflare.com/client/v4/");
        var originalIPs = new List<string>();
        if (!string.IsNullOrEmpty(ip4) && ipv4Ids.Length > 0)
        {
            foreach (var ip4id in ipv4Ids)
            {
                if (cancellationToken.IsCancellationRequested) break;
                var resp = await client.GetStreamAsync($"zones/{zone}/dns_records/{ip4id}", cancellationToken);
                var node = JsonNode.Parse(resp);
                System.Console.WriteLine(node?.ToJsonString());
                var originalIP = node?["result"]?["content"]?.ToString();
                if (!string.IsNullOrEmpty(originalIP))
                {
                    originalIPs.Add(originalIP);
                    if (originalIP == ip4)
                    {
                        continue;
                    }
                }
                await client.PatchAsync($"zones/{zone}/dns_records/{ip4id}", new StringContent($"{{\"content\":\"{ip4}\"}}", System.Text.Encoding.UTF8, "application/json"), cancellationToken);

            }
        }

        if (!string.IsNullOrEmpty(ip6) && ipv6Ids.Length > 0)
        {
            foreach (var ip6id in ipv6Ids)
            {
                if (cancellationToken.IsCancellationRequested) break;
                var resp = await client.GetStreamAsync($"zones/{zone}/dns_records/{ip6id}", cancellationToken);
                var node = JsonNode.Parse(resp);
                System.Console.WriteLine(node?.ToJsonString());
                var originalIP = node?["result"]?["content"]?.ToString();
                if (!string.IsNullOrEmpty(originalIP))
                {
                    originalIPs.Add(originalIP);
                    if (originalIP == ip6)
                    {
                        continue;
                    }
                }
                await client.PatchAsync($"zones/{zone}/dns_records/{ip6id}", new StringContent($"{{\"content\":\"{ip6}\"}}", System.Text.Encoding.UTF8, "application/json"), cancellationToken);
            }
        }

        return originalIPs.ToArray();

    }

    static async Task Notify(string token, string user, string[] devices, string ip4, string ip6, string[] originalIPs, IServiceProvider services, CancellationToken cancellationToken)
    {
        var clientFactory = services.GetRequiredService<IHttpClientFactory>();
        var client = clientFactory.CreateClient("apiclient");

        var message = ip4 + "\n";
        if(!string.IsNullOrEmpty(ip6))
        {
            message += ip6 + "\n";
        }
        message += "\nOriginal:\n";
        message += string.Join('\n', originalIPs);

        var msg = new JsonObject{
            ["token"] = token,
            ["user"] = user,
            ["title"] = "Home Pi IP Updated.",
            ["message"] = message
        };
        if(devices.Length > 0) {
            msg["device"] = string.Join(',', devices);
        }

        await client.PostAsync("https://api.pushover.net/1/messages.json",new StringContent(msg.ToJsonString(), System.Text.Encoding.UTF8, "application/json"));
    }

}
