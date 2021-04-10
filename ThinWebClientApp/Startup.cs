﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using IPA.Cores.Basic;
using IPA.Cores.Helper.Basic;
using static IPA.Cores.Globals.Basic;

using IPA.Cores.Web;
using IPA.Cores.Helper.Web;
using static IPA.Cores.Globals.Web;

using IPA.Cores.Codes;
using IPA.Cores.Helper.Codes;
using static IPA.Cores.Globals.Codes;

using static IPA.App.ThinWebClientApp.AppGlobal;
using System.Threading;
using System.Net;
using System.Net.Sockets;

#pragma warning disable CS1998 // 非同期メソッドは、'await' 演算子がないため、同期的に実行されます

namespace IPA.App.ThinWebClientApp
{
    public class MyThinWebClientHook : ThinWebClientHookBase
    {
    }

    public class MyThinWebClientFactory : SharedObjectFactory<ThinWebClient>
    {
        public static readonly MyThinWebClientFactory Factory = new MyThinWebClientFactory();

        protected override ThinWebClient CreateNewImpl()
        {
            ThinWebClientSettings settings = new ThinWebClientSettings
            {
            };

            MyThinWebClientHook hook = new MyThinWebClientHook();

            return new ThinWebClient(settings, hook);
        }
    }

    public class Startup
    {
        readonly HttpServerStartupHelper StartupHelper;
        readonly AspNetLib AspNetLib;
        readonly SharedObjectHolder<ThinWebClient> ClientHolder;

        public ThinWebClient Client => ClientHolder.Object;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            // HttpServer ヘルパーの初期化
            StartupHelper = new HttpServerStartupHelper(configuration);

            // AspNetLib の初期化: 必要な機能のみ ON にすること
            AspNetLib = new AspNetLib(configuration, AspNetLibFeatures.None);

            // ThinWebClient インスタンスを作成 (Http サーバーのインスタンスが複数存在することを想定しているため、共有させる)
            this.ClientHolder = MyThinWebClientFactory.Factory.CreateOrGet();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // AspNetLib による設定を追加
            AspNetLib.ConfigureServices(StartupHelper, services);

            // 基本的な設定を追加
            StartupHelper.ConfigureServices(services);

            // Razor ページを追加
            services.AddRazorPages();

            // MVC 機能を追加
            services.AddControllersWithViews()
                .ConfigureMvcWithAspNetLib(AspNetLib);

            // シングルトンサービスの注入
            services.AddSingleton(Client);

            // 全ページ共通コンテキストの注入
            services.AddScoped<PageContext>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IHostApplicationLifetime lifetime)
        {
            // wwwroot ディレクトリを static ファイルのルートとして追加
            StartupHelper.AddStaticFileProvider(Env.AppRootDir._CombinePath("wwwroot"));

            // AspNetLib による設定を追加
            AspNetLib.Configure(StartupHelper, app, env);

            // 基本的な設定を追加
            StartupHelper.Configure(app, env);

            // エラーページを追加
            if (StartupHelper.IsDevelopmentMode)
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/ThinWebClient/Error");
            }

            // エラーログを追加
            app.UseHttpExceptionLogger();

            // Static ファイルを追加
            app.UseStaticFiles();

            // WebSocket を追加
            app.UseWebSockets(new Microsoft.AspNetCore.Builder.WebSocketOptions
            {
                KeepAliveInterval = 5000._ToTimeSpanMSecs(),
            });

            // ルーティングを有効可
            app.UseRouting();

            // 認証・認可を実施
            app.UseAuthentication();
            app.UseAuthorization();

            // ルートマップを定義
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=ThinWebClient}/{action=Start}/{id?}");
            });

            // クリーンアップ動作を定義
            lifetime.ApplicationStopping.Register(() =>
            {
                AspNetLib._DisposeSafe();
                StartupHelper._DisposeSafe();

                ClientHolder._DisposeSafe();
            });
        }
    }
}