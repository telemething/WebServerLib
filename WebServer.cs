using EmbedIO;
using EmbedIO.WebApi;
using System;
using System.IO;
using System.Net;
using EmbedIO.Actions;
using EmbedIO.Routing;
using System.Threading.Tasks;
using System.Diagnostics;

using System.Collections.Concurrent;
using System.Linq;
using System.Net.WebSockets;
using EmbedIO.WebSockets;

using System.Threading;
using EmbedIO.Files;
using EmbedIO.Security;

using Swan.Logging;

using System.Collections.Generic;
using System.Collections.Specialized;

using EmbedIO.Utilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace WebApiLib
{
    public enum MessageTypeEnum { unknown, request, response, connection }
    public enum ResultEnum { unknown, notfound, ok, timeout, exception }

    //*************************************************************************
    /// <summary>
    /// WebApi argument
    /// </summary>
    //*************************************************************************
    public class Argument
    {
        public string Name { set; get; }
        public object Value { set; get; }
        public Type Type { set; get; }

        public Argument(string name, object value)
        {
            Name = name;
            Value = value;
            Type = value.GetType();
        }
    }

    //*************************************************************************
    /// <summary>
    /// WebApi Request
    /// </summary>
    //*************************************************************************
    public class Request
    {
        public Guid GUID { set; get; }

        public string MethodName { set; get; }

        public List<Argument> Arguments { set; get; }

        public Request(string methodName, List<Argument> arguments)
        {
            MethodName = methodName;
            Arguments = arguments;
            GUID = new Guid();
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        //*********************************************************************
        public static Request Deserialize(string data)
        {
            var settings = new JsonSerializerSettings {
                NullValueHandling = NullValueHandling.Ignore, 
                MissingMemberHandling = MissingMemberHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.DeserializeObject<Request>(data, settings);
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        public string Serialize()
        {
            var settings = new JsonSerializerSettings { 
                NullValueHandling = NullValueHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.SerializeObject(this, settings);
        }
    }

    //*************************************************************************
    /// <summary>
    /// WebApi Response
    /// </summary>
    //*************************************************************************
    public class Response
    {
        public Guid RequestGUID { set; get; }

        public ResultEnum Result { set; get; }

        public List<Argument> Arguments { set; get; }

        public Exception Exception { set; get; }

        public Response(Guid requestGUID, ResultEnum result, 
            List<Argument> arguments, Exception exception)
        {
            RequestGUID = requestGUID;
            Result = result;
            Arguments = Arguments;
            Exception = exception;
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        //*********************************************************************
        public static Response Deserialize(string data)
        {
            var settings = new JsonSerializerSettings { 
                NullValueHandling = NullValueHandling.Ignore, 
                MissingMemberHandling = MissingMemberHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.DeserializeObject<Response>(data, settings);
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        public string Serialize()
        {
            var settings = new JsonSerializerSettings { 
                NullValueHandling = NullValueHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.SerializeObject(this, settings);
        }
    }

    //*************************************************************************
    /// <summary>
    /// WebApi Message
    /// </summary>
    //*************************************************************************
    public class Message
    {
        public MessageTypeEnum MessageType { set; get; }
        public Request Request { set; get; }
        public Response Response { set; get; }

        public Message()
        {
            MessageType = MessageTypeEnum.unknown;
        }
        public Message(Request request)
        {
            Request = request;
            MessageType = MessageTypeEnum.request;
        }
        public Message(Response response)
        {
            Response = response;
            MessageType = MessageTypeEnum.response;
        }
        public Message(MessageTypeEnum messageType)
        {
            MessageType = messageType;
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        //*********************************************************************
        public static Message Deserialize(string data)
        {
            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore, MissingMemberHandling = MissingMemberHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.DeserializeObject<Message>(data, settings);
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        public string Serialize()
        {
            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
            return JsonConvert.SerializeObject(this, settings);
        }

    }

    //*************************************************************************
    /// <summary>
    /// Web API Client
    /// </summary>
    //*************************************************************************
    public class WebApiClient
    {
        WebServerLib.TTWebSocketClient _client = new WebServerLib.TTWebSocketClient();
        private EventWaitHandle _gotNewResponse = new EventWaitHandle(false, EventResetMode.ManualReset);
        Queue<Request> RequestsReceived = new Queue<Request>();
        Queue<Response> ResponsesReceived = new Queue<Response>();
        bool _connectedToApi = false;

        //*********************************************************************
        /// <summary>
        /// Connect to a server
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        //*********************************************************************
        public bool Connect(string url)
        {
            _client.Connect(url);
            _client.Listen(GotMessageCallback, CancellationToken.None);

            //while(!_connectedToApi)
            //{
            //    Thread.Sleep(100);
            //}

            return true;
        }

        //*********************************************************************
        /// <summary>
        /// Invoke a WebApi method
        /// </summary>
        /// <param name="methodName"></param>
        /// <param name="argumentList"></param>
        /// <param name="timeoutMs"></param>
        /// <returns></returns>
        //*********************************************************************
        public async Task<Response> Invoke(string methodName, 
            List<Argument> argumentList, int timeoutMs = 15000)
        {
            Response response = null;

            var request = new Request(methodName, argumentList);

            // send to server
            _client.Send(request.Serialize());

            // wait for response
            while (true)
            {
                try
                {
                    if (_gotNewResponse.WaitOne(timeoutMs))
                    {
                        response = ResponsesReceived.Dequeue();
                    }
                    else
                    {
                        response = new Response(request.GUID, ResultEnum.timeout, null, null);
                    }
                }
                catch (Exception ex)
                {
                    response = new Response(request.GUID, ResultEnum.exception, null, ex);
                }

                break;
            }

            return response;
        }

        //*********************************************************************
        /// <summary>
        /// Called by the WebSocket client when a message is received
        /// </summary>
        /// <param name="data"></param>
        //*********************************************************************
        private void GotMessageCallback(string data)
        {
            //what kind of message is this?

            var message = Message.Deserialize(data); 

            switch( message.MessageType)
            {
                case MessageTypeEnum.connection:
                    _connectedToApi = true;
                    break;
                case MessageTypeEnum.request:
                    break;
                case MessageTypeEnum.response:
                    ResponsesReceived.Enqueue(message.Response);
                    _gotNewResponse.Set();
                    break;
            }
        }
    }
}

namespace WebServerLib
{
    #region WebSocketClient

    //https://docs.microsoft.com/en-us/dotnet/api/system.net.websockets.clientwebsocket?view=netstandard-2.0
    //https://thecodegarden.net/websocket-client-dotnet

    //*************************************************************************
    /// <summary>
    /// Web socket client
    /// </summary>
    //*************************************************************************
    public class TTWebSocketClient
    {
        public delegate void GotMessageCallback(string data);

        private GotMessageCallback _gotMessageCallback;

        ClientWebSocket sock = new ClientWebSocket();

        public TTWebSocketClient()
        { }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        //*********************************************************************
        public void Connect(string url)
        {
            try
            {
                sock.ConnectAsync(new Uri(url), CancellationToken.None);
                //Receive(CancellationToken.None);
            }
            catch (Exception ex)
            {
                var msg = ex.Message;
            }
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        //*********************************************************************
        public void Connect()
        {
            Connect("ws://localhost:8877/chat");
        }

        //*********************************************************************
        /// <summary>
        /// Send a message
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        //*********************************************************************
        public async Task Send(string data)
        {
            try
            {
                while(sock.State != WebSocketState.Open)
                {
                    Thread.Sleep(500);
                }
                //Receive(CancellationToken.None);
                var aseg = new ArraySegment<byte>(System.Text.Encoding.UTF8.GetBytes(data));
                await sock.SendAsync(aseg, WebSocketMessageType.Text, true, CancellationToken.None);
            }
            catch (Exception ex)
            {
                var msg = ex.Message;
            }
        }

        //*********************************************************************
        /// <summary>
        /// Listem for messages, call callback when a message is received
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="stoppingToken"></param>
        //*********************************************************************
        public async void Listen(GotMessageCallback callback, 
            CancellationToken stoppingToken)
        {
            _gotMessageCallback = callback;

            var buffer = new ArraySegment<byte>(new byte[2048]);

            while (sock.State != WebSocketState.Open)
            {
                Thread.Sleep(50);
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                WebSocketReceiveResult result;
                using (var ms = new MemoryStream())
                {
                    do
                    {
                        result = await sock.ReceiveAsync(buffer, stoppingToken);
                        ms.Write(buffer.Array, buffer.Offset, result.Count);
                    } while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close)
                        break;

                    ms.Seek(0, SeekOrigin.Begin);
                    using (var reader = new StreamReader(ms, System.Text.Encoding.UTF8))
                    {
                        //Console.WriteLine(await reader.ReadToEndAsync());
                        
                        string data = await reader.ReadToEndAsync();
                        _gotMessageCallback?.Invoke(data);
                    }
                }
            };

        }
    }

    #endregion

    #region ChatServer

    //**********************************************************************
    //**********************************************************************
    //**********************************************************************
    //**********************************************************************

    //https://unosquare.github.io/embedio/#websockets-example
    //https://github.com/unosquare/embedio/blob/master/src/samples/EmbedIO.Samples/Program.cs

    //*************************************************************************
    /// <summary>
    /// Web socket server
    /// </summary>
    //*************************************************************************
    public class TTWebSocketServer
    {
        private const bool UseFileCache = true;
        CancellationTokenSource cts = new CancellationTokenSource();

        // Gets the local path of shared files.
        // When debugging, take them directly from source so we can edit and reload.
        // Otherwise, take them from the deployment directory.
        public static string HtmlRootPath
        {
            get
            {
                var assemblyPath = Path.GetDirectoryName(typeof(TTWebSocketServer).Assembly.Location);

#if DEBUG
                return Path.Combine(Directory.GetParent(assemblyPath).Parent.Parent.FullName, "html");
#else
                return Path.Combine(assemblyPath, "html");
#endif
            }
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        //*********************************************************************
        private static WebServer CreateWebServer(string url)
        {
#pragma warning disable CA2000 // Call Dispose on object - this is a factory method.
            try
            {
                var server = new WebServer(o => o
                        .WithUrlPrefix(url)
                        .WithMode(HttpListenerMode.EmbedIO))
                    .WithIPBanning(o => o
                        .WithMaxRequestsPerSecond()
                        .WithRegexRules("HTTP exception 404"))
                    .WithLocalSessionManager()
                    .WithCors(
                        "http://www.telemething.com,http://api.telemething.com", // Origins, separated by comma without last slash
                        "content-type, accept", // Allowed headers
                        "post") // Allowed methods
                    .WithWebApi("/api", m => m
                        .WithController<PeopleController>())
                    .WithModule(new WebSocketWebApiModule("/chat"))
                    .WithModule(new WebSocketTerminalModule("/terminal"))
                    .WithStaticFolder("/", HtmlRootPath, true, m => m
                        .WithContentCaching(UseFileCache)) // Add static files after other modules to avoid conflicts
                    .WithModule(new ActionModule("/", HttpVerbs.Any, ctx => ctx.SendDataAsync(new { Message = "Error" })));

                // Listen for state changes.
                server.StateChanged += (s, e) => $"WebServer New State - {e.NewState}".Info();

                return server;
            }
            catch (Exception ex)
            {
                var ff = ex.Message;
                return null;
            }

#pragma warning restore CA2000
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        //*********************************************************************
        private static async Task RunWebServerAsync(string url, CancellationToken cancellationToken)
        {
            using (var server = CreateWebServer(url))
            {
                await server.RunAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        //*********************************************************************
        public void StartServer()
        {
            var url = "http://*:8877";

            RunWebServerAsync(url, cts.Token);
        }
    }


    public class TTWebSocketServerOrig
    {
        private const bool UseFileCache = true;
        CancellationTokenSource cts = new CancellationTokenSource();

        // Gets the local path of shared files.
        // When debugging, take them directly from source so we can edit and reload.
        // Otherwise, take them from the deployment directory.
        public static string HtmlRootPath
        {
            get
            {
                var assemblyPath = Path.GetDirectoryName(typeof(TTWebSocketServerOrig).Assembly.Location);

#if DEBUG
                return Path.Combine(Directory.GetParent(assemblyPath).Parent.Parent.FullName, "html");
#else
                return Path.Combine(assemblyPath, "html");
#endif
            }
        }

        // Create and configure our web server.
        private static WebServer CreateWebServer(string url)
        {
#pragma warning disable CA2000 // Call Dispose on object - this is a factory method.
            try
            {
                var server = new WebServer(o => o
                        .WithUrlPrefix(url)
                        .WithMode(HttpListenerMode.EmbedIO))
                    .WithIPBanning(o => o
                        .WithMaxRequestsPerSecond()
                        .WithRegexRules("HTTP exception 404"))
                    .WithLocalSessionManager()
                    .WithCors(
                        "http://unosquare.github.io,http://run.plnkr.co", // Origins, separated by comma without last slash
                        "content-type, accept", // Allowed headers
                        "post") // Allowed methods
                    .WithWebApi("/api", m => m
                        .WithController<PeopleController>())
                    .WithModule(new WebSocketChatModule("/chat"))
                    .WithModule(new WebSocketTerminalModule("/terminal"))
                    .WithStaticFolder("/", HtmlRootPath, true, m => m
                        .WithContentCaching(UseFileCache)) // Add static files after other modules to avoid conflicts
                    .WithModule(new ActionModule("/", HttpVerbs.Any, ctx => ctx.SendDataAsync(new { Message = "Error" })));

                // Listen for state changes.
                server.StateChanged += (s, e) => $"WebServer New State - {e.NewState}".Info();

                return server;
            }
            catch(Exception ex)
            {
                var ff = ex.Message;
                return null;
            }

#pragma warning restore CA2000
        }

        // Create and run a web server.
        private static async Task RunWebServerAsync(string url, CancellationToken cancellationToken)
        {
            using (var server = CreateWebServer(url))
            {
                await server.RunAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public void StartServer()
        {
            var url = "http://*:8877";

            RunWebServerAsync(url, cts.Token);
        }

    }

    //*************************************************************************
    /// <summary>
    /// Websocket WebAPI Module
    /// </summary>
    //*************************************************************************
    public class WebSocketWebApiModule : WebSocketModule
    {
        public WebSocketWebApiModule(string urlPath)
            : base(urlPath, true)
        {
            // placeholder
        }

        /// <inheritdoc />
        protected override Task OnMessageReceivedAsync(
            IWebSocketContext context,
            byte[] rxBuffer,
            IWebSocketReceiveResult rxResult)
            => SendAsync(context, new WebApiLib.Message(new WebApiLib.Response(new Guid(), WebApiLib.ResultEnum.ok, new List<WebApiLib.Argument>(), null)));

        /// <inheritdoc />
        protected override Task OnClientConnectedAsync(IWebSocketContext context)
            => SendAsync(context, new WebApiLib.Message(WebApiLib.MessageTypeEnum.connection));

        /// <inheritdoc />
        protected override Task OnClientDisconnectedAsync(IWebSocketContext context)
            => SendToOthersAsync(context, "Someone left the chat room.");

        private Task SendToOthersAsync(IWebSocketContext context, string payload)
            => BroadcastAsync(payload, c => c != context);

        private Task SendAsync(IWebSocketContext context, WebApiLib.Message message)
        {
            return SendAsync(context, message.Serialize());
        }
    }

    //*************************************************************************
    /// <summary>
    /// Defines a very simple chat server.
    /// </summary>
    //*************************************************************************
    public class WebSocketChatModule : WebSocketModule
    {
        public WebSocketChatModule(string urlPath)
            : base(urlPath, true)
        {
            // placeholder
        }

        /// <inheritdoc />
        protected override Task OnMessageReceivedAsync(
            IWebSocketContext context,
            byte[] rxBuffer,
            IWebSocketReceiveResult rxResult)
            => SendToOthersAsync(context, Encoding.GetString(rxBuffer));

        /// <inheritdoc />
        protected override Task OnClientConnectedAsync(IWebSocketContext context)
            => Task.WhenAll(
                SendAsync(context, "Welcome to the chat room!"),
                SendToOthersAsync(context, "Someone joined the chat room."));

        /// <inheritdoc />
        protected override Task OnClientDisconnectedAsync(IWebSocketContext context)
            => SendToOthersAsync(context, "Someone left the chat room.");

        private Task SendToOthersAsync(IWebSocketContext context, string payload)
            => BroadcastAsync(payload, c => c != context);
    }

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************

    public sealed class PeopleController : WebApiController
    {
        // Gets all records.
        // This will respond to
        //     GET http://localhost:9696/api/people
        [Route(HttpVerbs.Get, "/people")]
        public Task<IEnumerable<Person>> GetAllPeople() => Person.GetDataAsync();

        // Gets the first record.
        // This will respond to
        //     GET http://localhost:9696/api/people/first
        [Route(HttpVerbs.Get, "/people/first")]
        public async Task<Person> GetFirstPeople() => (await Person.GetDataAsync().ConfigureAwait(false)).First();

        // Gets a single record.
        // This will respond to
        //     GET http://localhost:9696/api/people/1
        //     GET http://localhost:9696/api/people/{n}
        //
        // If the given ID is not found, this method will return false.
        // By default, WebApiModule will then respond with "404 Not Found".
        //
        // If the given ID cannot be converted to an integer, an exception will be thrown.
        // By default, WebApiModule will then respond with "500 Internal Server Error".
        [Route(HttpVerbs.Get, "/people/{id?}")]
        public async Task<Person> GetPeople(int id)
            => (await Person.GetDataAsync().ConfigureAwait(false)).FirstOrDefault(x => x.Id == id)
            ?? throw HttpException.NotFound();

        // Posts the people Tubular model.
        /*[Route(HttpVerbs.Post, "/people")]
        public async Task<GridDataResponse> PostPeople([JsonGridDataRequest] GridDataRequest gridDataRequest)
            => gridDataRequest.CreateGridDataResponse((await Person.GetDataAsync().ConfigureAwait(false)).AsQueryable());*/

        // Echoes request form data in JSON format.
        [Route(HttpVerbs.Post, "/echo")]
        public Dictionary<string, object> Echo([FormData] NameValueCollection data)
            => data.ToDictionary();

        // Select by name
        [Route(HttpVerbs.Get, "/peopleByName/{name}")]
        public async Task<Person> GetPeopleByName(string name)
            => (await Person.GetDataAsync().ConfigureAwait(false)).FirstOrDefault(x => x.Name == name)
            ?? throw HttpException.NotFound();
    }

    /*[AttributeUsage(AttributeTargets.Parameter)]
    public class JsonGridDataRequestAttribute : Attribute, INonNullRequestDataAttribute<WebApiController, GridDataRequest>
    {
        public Task<GridDataRequest> GetRequestDataAsync(WebApiController controller, string parameterName)
            => Validate.NotNull(nameof(controller), controller).HttpContext.GetRequestDataAsync(RequestDeserializer.Json<GridDataRequest>);
    }*/

    public class Person
    {
        public int Id { get; set; }

        public string Name { get; set; }

        public int Age { get; set; }

        public string EmailAddress { get; set; }

#pragma warning disable 0618 // "Use a better hasher." - Not our fault if gravatar.com uses MD5.
        //public string PhotoLocation => $"http://www.gravatar.com/avatar/{Hasher.ComputeMD5(EmailAddress).ToUpperHex()}.png?s=100";
        public string PhotoLocation => "---";
#pragma warning restore 0618

        internal static async Task<IEnumerable<Person>> GetDataAsync()
        {
            // Imagine this is a database call :)
            await Task.Delay(0).ConfigureAwait(false);

            return new List<Person>
            {
                new Person
                {
                    Id = 1,
                    Name = "Mario Di Vece",
                    Age = 31,
                    EmailAddress = "mario@unosquare.com",
                },
                new Person
                {
                    Id = 2,
                    Name = "Geovanni Perez",
                    Age = 32,
                    EmailAddress = "geovanni.perez@unosquare.com",
                },
                new Person
                {
                    Id = 3,
                    Name = "Luis Gonzalez",
                    Age = 29,
                    EmailAddress = "luis.gonzalez@unosquare.com",
                },
            };
        }
    }

    #endregion

    #region ChatTerminal

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************

    public class WebSocketTerminalModule : WebSocketModule
    {
        private readonly ConcurrentDictionary<IWebSocketContext, Process> _processes = new ConcurrentDictionary<IWebSocketContext, Process>();

        public WebSocketTerminalModule(string urlPath)
            : base(urlPath, true)
        {
        }

        /// <inheritdoc />
        protected override Task OnMessageReceivedAsync(IWebSocketContext context, byte[] buffer, IWebSocketReceiveResult result)
            => _processes.TryGetValue(context, out var process)
                ? process.StandardInput.WriteLineAsync(Encoding.GetString(buffer))
                : Task.CompletedTask;

        /// <inheritdoc />
        protected override Task OnClientConnectedAsync(IWebSocketContext context)
        {
#pragma warning disable CA2000 // Call Dispose on object - will do in OnClientDisconnectedAsync.
            var process = new Process
            {
                EnableRaisingEvents = true,
                StartInfo = new ProcessStartInfo
                {
                    CreateNoWindow = true,
                    ErrorDialog = false,
                    FileName = "cmd.exe",
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    WorkingDirectory = Environment.CurrentDirectory,
                },
            };
#pragma warning restore CA2000

            process.OutputDataReceived += async (s, e) => await SendBufferAsync(s as Process, e.Data).ConfigureAwait(false);

            process.ErrorDataReceived += async (s, e) => await SendBufferAsync(s as Process, e.Data).ConfigureAwait(false);

            process.Exited += async (s, e) =>
            {
                var ctx = FindContext(s as Process);
                if (ctx?.WebSocket?.State == WebSocketState.Open)
                    await CloseAsync(ctx).ConfigureAwait(false);
            };

            _processes.TryAdd(context, process);

            process.Start();
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override Task OnClientDisconnectedAsync(IWebSocketContext context)
        {
            if (_processes.TryRemove(context, out var process))
            {
                if (!process.HasExited)
                    process.Kill();

                process.Dispose();
            }

            return Task.CompletedTask;
        }

        private IWebSocketContext FindContext(Process p)
            => _processes.FirstOrDefault(kvp => kvp.Value == p).Key;

        private Task SendBufferAsync(Process process, string buffer)
        {
            try
            {
                if (process.HasExited)
                    return Task.CompletedTask;

                var context = FindContext(process);
                return context?.WebSocket?.State == WebSocketState.Open
                    ? SendAsync(context, buffer)
                    : Task.CompletedTask;
            }
            catch
            {
                // ignore process teermination
                return Task.CompletedTask;
            }
        }
    }

    #endregion

    #region HTTP

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************
    public class TTWebServer
    {
        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        //*********************************************************************
        public void StartServer()
        {
            // Handle when your app starts
            System.Threading.Tasks.Task.Factory.StartNew(async () =>
            {
                try
                {
                    using (var server = new WebServer(HttpListenerMode.EmbedIO, "http://*:8080"))
                    {
                        //Assembly assembly = typeof(App).Assembly;
                        server.WithLocalSessionManager();
                        server.WithWebApi("/tiles", m => m.WithController(() => new TileController()));
                        server.WithWebApi("/config", m => m.WithController(() => new ConfigController()));
                        //server.WithEmbeddedResources("/", assembly, "EmbedIO.Forms.Sample.html");
                        await server.RunAsync();
                    }
                }
                catch (System.Exception ex)
                {
                    Debug.WriteLine(ex.ToString());
                }
            });
        }
    }

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************
    public class TileController : WebApiController
    {
        public TileController() : base()
        { }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        [Route(HttpVerbs.Get, "/testresponse")]
        public int GetTestResponse()
        {
            var data = HttpContext;

            return 12345;
        }

        //*********************************************************************
        /// <summary>
        /// "http://dev.virtualearth.net/REST/v1/Elevation/Bounds?bounds={0},{1},{2},{3}&rows=11&cols=11&key={4}"
        /// southWest.Lat, southWest.Lon, northEast.Lat, northEast.Lon, _mapToken
        /// </summary>
        /// <returns></returns>
        //*********************************************************************

        [Route(HttpVerbs.Get, "/Elevation/Bounds")]
        public int GetElevation()
        {

            var addr = Dns.GetHostAddresses(Dns.GetHostName());

            var context = HttpContext;

            var qd = context.GetRequestQueryData();

            string[] values = null;

            foreach (string key in qd.Keys)
            {
                values = qd.GetValues(key);
                foreach (string value in values)
                {
                    //MessageBox.Show(key + " - " + value);
                }
            }

            return 12345;
        }

        //*********************************************************************
        /// <summary>
        /// "http://{0}.tile.openstreetmap.org/{1}/{2}/{3}.png"
        /// TilePathPrefixes[Mathf.Abs(tileInfo.X) % 3],tileInfo.ZoomLevel, tileInfo.X, tileInfo.Y)
        /// https://docs.microsoft.com/en-us/aspnet/web-api/overview/web-api-routing-and-actions/create-a-rest-api-with-attribute-routing
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        /*[Route(HttpVerbs.Get, "/{zoom:int}/{x:int}/{y:int}.png")]
        public int GetImage(int zoom, int x, int y)
        {
            var data = HttpContext;

            return 12345;
        }*/
    }

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************
    public class ConfigController : WebApiController
    {
        public ConfigController() : base()
        { }

        //*********************************************************************
        /// <summary>
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        [Route(HttpVerbs.Get, "/Full")]
        public int GetElevation()
        {

            var addr = Dns.GetHostAddresses(Dns.GetHostName());

            var context = HttpContext;

            var qd = context.GetRequestQueryData();

            string[] values = null;

            foreach (string key in qd.Keys)
            {
                values = qd.GetValues(key);
                foreach (string value in values)
                {
                    //MessageBox.Show(key + " - " + value);
                }
            }

            return 12345;
        }
    }

    //*************************************************************************
    /// <summary>
    /// 
    /// </summary>
    //*************************************************************************
    public class TileClient
    {
        private const string DefaultUrl = "http://localhost:8080/";

        private string _result;
        public string Result
        {
            get { return _result; }
            set
            {
                _result = value;
                //OnPropertyChanged("Result");
            }
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        //*********************************************************************
        private async Task AcceptEncoding_None()
        {
            try
            {
                //var URL = $"{DefaultUrl}api/Elevation/Bounds?bounds={0},{1},{2},{3}&rows=11&cols=11&key={4}";
                //var URL = $"{DefaultUrl}bpi/Elevation/Bounds?bounds={0},{1},{2},{3}&rows=11&cols=11&key={4}";
                var URL = $"{DefaultUrl}config/Full";

                Result = $"Trying AcceptEncoding = None{System.Environment.NewLine}";

                using (var client = new System.Net.Http.HttpClient())
                {
                    //using (var response = await client.GetAsync($"{DefaultUrl}api/testresponse/?bounds=b1").ConfigureAwait(false))
                    using (var response = await client.GetAsync(URL).ConfigureAwait(false))
                    {
                        var responseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        Result += "Result = " + (string.IsNullOrEmpty(responseString) ? "<Empty>" : responseString);
                    }
                }
            }
            catch (System.Exception ex)
            {
                Debug.WriteLine(ex.ToString());
            }
        }

        //*********************************************************************
        /// <summary>
        /// 
        /// </summary>
        //*********************************************************************
        public async void Test()
        {
            while(true)
            {
                System.Threading.Thread.Sleep(1000);
                await AcceptEncoding_None();
            }
        }
    }

    #endregion
}
