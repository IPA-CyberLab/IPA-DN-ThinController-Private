// Thin Telework System Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.

// この Vars.cs ファイルは、シン・テレワークシステムを設置するユーザー側で書き換えて動作をカスタマイズするためのファイルです。

#pragma warning disable CA2235 // Mark all non-serializable fields
#pragma warning disable CS1998 // 非同期メソッドは、'await' 演算子がないため、同期的に実行されます

using System;
using System.Buffers;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Https;

using IPA.Cores.Basic;
using IPA.Cores.Helper.Basic;
using static IPA.Cores.Globals.Basic;

using IPA.Cores.Web;
using IPA.Cores.Helper.Web;
using static IPA.Cores.Globals.Web;

using IPA.Cores.Codes;
using IPA.Cores.Helper.Codes;
using static IPA.Cores.Globals.Codes;

namespace IPA.App.ThinVars
{
    public static partial class ThinVarsGlobal
    {
        // 初期化
        public static void InitMain()
        {
            // 許容する TLS のバージョンを設定するには、以下の行をコメントアウトして設定を変更すること。
            //CoresConfig.SslSettings.DefaultSslProtocolVersionsAsClient.TrySet(SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13);
            //CoresConfig.SslSettings.DefaultSslProtocolVersionsAsServer.TrySet(SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13);
        }

        // 証明書データを保持するクラス
        public static partial class Certs
        {
            // マスター証明書 (X.509 PEM 形式)
            // このサンプルコードでは、ソースコードツリー中の
            // Vars/VarResources/VarResources/ThinControllerCerts/00_Master.cer
            // ファイルをマスター証明書として取り扱っています。
            // マスター証明書の置換は、以下のファイル名を変更するか、または、上記のファイルに使用したい証明書データファイルを上書きすることで可能です。
            static readonly Singleton<PalX509Certificate> MasterCert_Singleton =
                new Singleton<PalX509Certificate>(() => new PalX509Certificate(new FilePath(AppGlobal.AppRes, 
                    "ThinControllerCerts/00_Master.cer")));

            public static PalX509Certificate MasterCert => MasterCert_Singleton;

            // コントローラの HTTPS サーバー証明書と秘密鍵 (PKCS#12 形式)
            // このサンプルコードでは、ソースコードツリー中の
            // Vars/VarResources/VarResources/ThinControllerCerts/02_Controller.pfx
            // ファイルをコントローラの HTTPS サーバー証明書と秘密鍵として取り扱っています。
            // コントローラの HTTPS サーバー証明書と秘密鍵の置換は、以下のファイル名を変更するか、または、上記のファイルに使用したい証明書データファイルを上書きすることで可能です。
            static readonly Singleton<PalX509Certificate> ControllerCert_Singleton =
                new Singleton<PalX509Certificate>(() => new PalX509Certificate(new FilePath(AppGlobal.AppRes, 
                    "ThinControllerCerts/02_Controller.pfx")));

            public static PalX509Certificate ControllerCert => ControllerCert_Singleton;

            // HTML5 クライアント証明書認証 ルート CA 証明書 (X.509 PEM 形式)
            // このサンプルコードでは、ソースコードツリー中の
            // Vars/VarResources/VarResources/ThinWebClient_ClientCertAuth_SampleCerts/01_thin_html5_cert_auth_sample_root_ca.cer
            // ファイルを HTML5 クライアント証明書認証 ルート CA 証明書として取り扱っています。
            // HTML5 クライアント証明書認証 ルート CA 証明書の置換は、以下のファイル名を変更するか、または、上記のファイルに使用したい証明書データファイルを上書きすることで可能です。
            static readonly Singleton<PalX509Certificate> Html5ClientCertAuth_RootCaCert_Singleton =
                new Singleton<PalX509Certificate>(() => new PalX509Certificate(new FilePath(AppGlobal.AppRes, 
                    "ThinWebClient_ClientCertAuth_SampleCerts/01_thin_html5_cert_auth_sample_root_ca.cer")));

            public static PalX509Certificate Html5ClientCertAuth_RootCaCert => Html5ClientCertAuth_RootCaCert_Singleton;
        }

        // コントローラ固有の設定クラス
        public static partial class ThinControllerVarsConfig
        {
            public static void InitMain()
            {
                //////// --- ここから シン・テレワークシステム プライベート版を用いて有償の商用サービスを実装したいユーザー (システム開発者) 向けの機能です。以下の設定を変更して商用サービスを構築できます。 ---
                // 商用サービス化機能の有効化フラグ (true で有効)
                ThinControllerGlobalSettings.PaidService_Enabled.TrySetValue(true);

                // 体験版としての動作が開始された後、どれくらいの時間で体験版の利用期限が切れるかの設定。TimeSpan 構造体のコンストラクタを設定するものである。設定方法は TimeSpan 構造体のコンストラクタのドキュメントを参照せよ。
                // TimeSpan 構造体のドキュメント: https://docs.microsoft.com/ja-jp/dotnet/api/system.timespan
                ThinControllerGlobalSettings.PaidService_TrialSpan.TrySetValue(new TimeSpan(0, 0, 1, 0));

                // 体験版の利用期限が切れたか、製品版のアクティベーションが切れた場合に表示される Web ページの URL
                // <PCID>: コンピュータ名
                // <STATUS>: TrialExpired または Deactivated のいずれか
                // <EXPIRED>: STATUS が TrialExpired の場合、体験版の有効期限が切れた日時。Status が Deactivated の場合、解約された日。YYYYMMDDHHMMSS 形式
                // <TAG>: アクティベーションまたはアクティベーション解除時に指定されたタグ文字列
                ThinControllerGlobalSettings.PaidService_RedirectUrl.TrySetValue("https://example.org/expired/?status=<STATUS>&expired=<EXPIRED>&pcid=<PCID>&tag=<TAG>");

                // HTTP RPC を呼び出す際の固定認証ユーザー名とパスワード文字列。この文字列は運用開始前に必ず変更し、秘密として保持すること。
                ThinControllerGlobalSettings.PaidService_RpcAuthUsername.TrySetValue("USERNAME_HERE");
                ThinControllerGlobalSettings.PaidService_RpcAuthPassword.TrySetValue("PASSWORD_HERE");
            }
        }

        // HTML5 版 Web クライアントアプリ固有の設定クラス
        public static partial class ThinWebClientVarsConfig
        {
            // 全体的な動作設定
            public static void InitMain()
            {
                // HTTPS Web サーバーの証明書マネージャ (CertVault) の初期設定
                // ※ この設定を変更する前に、一度でも ThinWebClient を起動した場合は、
                //    初回起動時に設定ファイル「ThinWebClientApp/Local/App_IPA.App.ThinWebClientApp/Config/CertVault/settings.json」が
                //    自動生成されている。
                //    その後にこの Vars.cs ファイルの内容を書き換えても、
                //    「ThinWebClientApp/Local/App_IPA.App.ThinWebClientApp/Config/CertVault/settings.json」
                //    ファイルの内容には適用されない。
                //    このような場合には、
                //    一度 ThinWebClient を終了し、
                //    「ThinWebClientApp/Local/App_IPA.App.ThinWebClientApp/Config/CertVault/settings.json」
                //    を削除してから再度 ThinWebClient を起動すると、以下の内容が適用される。

                // true に設定すると、Let's Encrypt を使用して証明書を自動取得・更新するように試みるようになる。
                // Let's Encrypt を使用する場合は true、使用しない場合は false に設定すること。
                // 通常は、Let's Encrypt を使用せず、証明書を別に管理し、
                // 静的証明書ファイル (ThinWebClientApp/Local/App_IPA.App.ThinWebClientApp/Config/CertVault/StaticCerts/default.pfx) を設置しメンテナンスすることを推奨する。
                CoresConfig.CertVaultSettings.DefaultUseAcme.TrySetValue(false);

                CoresConfig.CertVaultSettings.DefaultNonAcmeEnableAutoGenerateSubjectNameCert.TrySetValue(false);   // これは、false を設定することを推奨する。
            }

            // Web サーバーの設定
            public static void InitalizeWebServerConfig(HttpServerOptions opt)
            {
                // false にすると robots.txt ファイルを設置しなくなります。
                opt.DenyRobots = true;

                // true にすると HTTP ポートへのアクセス時に自動的に HTTPS ポートにリダイレクトするようになります。
                // 適切な SSL サーバー証明書が利用されていない場合、Web ブラウザで証明書エラーが発生します。
                opt.AutomaticRedirectToHttpsIfPossible = false;

                // 「NoCertificate」を「RequireCertificate」に変更することにより、クライアント証明書認証を強制します。
                opt.ClientCertficateMode = ClientCertificateMode.NoCertificate;

                // クライアント証明書認証を行なう場合は、クライアントが提示した証明書が受け入れ可能かどうかを検証する任意の判定式を以下に記述します。
                // 注意: クライアント証明書認証は、スタンドアロン版の ThinGate (中継ゲートウェイ) のリバースプロキシ機能を利用する場合には利用できません。
                if (opt.ClientCertficateMode == ClientCertificateMode.RequireCertificate)
                {
                    // 提示されたクライアント証明書を検証するためのコールバック関数です。
                    // true を返した場合は、認証に成功したとみなされます。
                    // false を返すか、例外が発生した場合、認証に失敗したとみなされます。
                    opt.ClientCertificateValidatorAsync = async (cert, chain, err) =>
                    {
                        Certificate clientCertObject = cert.AsPkiCertificate(); // この clientCertObject 変数に、クライアントが提示したクライアント証明書が入っています。

                        // 提示されたクライアント証明書が、サンプルのルート CA ファイル
                        // 「IPA-DNP-ThinController-Public/Vars/VarResources/VarResources/ThinWebClient_ClientCertAuth_SampleCerts/01_thin_html5_cert_auth_sample_root_ca.cer」
                        // によって署名されているかどうかを確認します。
                        // clientCertObject.CheckIfSignedByAnyOfParentCertificatesListOrExactlyMatch() メソッドの第一引数の配列には、
                        // 複数の CA 証明書を示す変数を指定できます。
                        // 以下のサンプルでは CA 証明書は 1 つしか指定していませんが、2 つ以上指定することもできます。
                        // この場合は、いずれかの CA 証明書によって署名されている場合、認証を通過することになります。
                        // また、通常の運用ではあまり推奨されませんが、独自のクライアント証明書ファイルそのものを
                        // clientCertObject.CheckIfSignedByAnyOfParentCertificatesListOrExactlyMatch() メソッドの第一引数の配列に
                        // 指定することにより、提示されたクライアント証明書と、第一引数で指定された証明書が完全一致する場合に
                        // 認証を通過させることも可能です。これは、非常に小規模な運用において有益です。
                        if (clientCertObject.CheckIfSignedByAnyOfParentCertificatesListOrExactlyMatch(
                            new Certificate[] {
                                Certs.Html5ClientCertAuth_RootCaCert,
                            },
                            out bool exactlyMatchToRootCa) == false)
                        {
                            // CA によって署名されていません。
                            throw new CoresLibException($"The client SSL certificate '{clientCertObject}' is not trusted by any of root CA certificates.");
                        }
                        else if (exactlyMatchToRootCa == false)
                        {
                            // 提示された証明書の有効期限が切れている場合は、認証に失敗させます。
                            if (cert.AsPkiCertificate().IsExpired())
                            {
                                throw new CoresLibException($"The client SSL certificate '{clientCertObject}' is expired or not valid. NotBefore = '{clientCertObject.NotBefore._ToDtStr()}', NotAfter = '{clientCertObject.NotAfter._ToDtStr()}'");
                            }
                        }

                        return true; // 認証に成功しました。
                    };
                }
            }
        }
    }

#if CORES_CODES_THINCONTROLLER
    // シンテレワークシステム コントローラの動作をカスタマイズするためのクラスです。
    public class MyThinControllerHook : ThinControllerHookBase
    {
        // OTP メールを送信する処理をカスタマイズするには、以下のメソッドの内容を書き換えてください。
        public override async Task<bool> SendOtpEmailAsync(ThinController controller, string otp, string emailTo, string emailFrom, string clientIp, string clientFqdn, string pcidMasked, string pcid,
            ThinControllerOtpServerSettings serverSettings, CancellationToken cancel = default)
        {
            if (serverSettings.AwsSnsRegionEndPointName._IsEmpty() || Str.IsPhoneNumber(emailTo) == false) // 宛先が電話番号以外 または AWS SNS アカウント情報未設定の場合
            {
                // 通常メール
                string subject = string.Format("ワンタイムパスワード (OTP): {0}  (サーバー: '{1}')", otp, pcidMasked);

                string body = string.Format("OTP: {0}\r\n\r\n「シン・テレワークシステム サーバー」にログイン要求が\r\nありましたので、予め設定されている本メールアドレスに上記の OTP\r\n(ワンタイムパスワード) をご通知いたします。\r\n\r\n[参考情報]\r\nアクセス日時: {1}\r\nアクセス先コンピュータ ID: '{2}'  (一部を伏せ字としている場合があります)\r\nアクセス元 IP アドレス: {3}\r\nアクセス元ホスト名: {4}\r\n\r\n\r\nこのメールには返信できません。\r\n\r\nメールアドレスを登録した覚えがない場合は、あなたのメールアドレスを\r\n第三者が誤って「シン・テレワークシステム サーバー」の OTP 送付先\r\nとして登録している可能性があります。その場合、本メールに応答する\r\n必要はありません。\r\n\r\n",
                    otp, DateTime.Now.ToString(), pcidMasked, clientIp, clientFqdn);

                return await SmtpUtil.SendAsync(new SmtpConfig(serverSettings.SmtpServerHostname, serverSettings.SmtpServerPort, false, serverSettings.SmtpServerUsername, serverSettings.SmtpServerPassword),
                    emailFrom, emailTo, subject, body, true, cancel);
            }
            else
            {
                // SMS (AWS を利用)
                await using AwsSns sns = new AwsSns(new AwsSnsSettings(serverSettings.AwsSnsRegionEndPointName, serverSettings.AwsSnsAccessKeyId, serverSettings.AwsSnsSecretAccessKey));

                string body = string.Format("OTP: {0}\r\n\r\nシンテレ SMS\r\n日時: {1}\r\nID: '{2}' (一部伏字)\r\nアクセス元: {3} ({4})\r\n",
                    otp, DateTime.Now.ToString(), pcidMasked, clientIp, clientFqdn);

                try
                {
                    await sns.SendAsync(body, emailTo, cancel);

                    return true;
                }
                catch (Exception ex)
                {
                    ex._Error();

                    return false;
                }
            }
        }
    }
#endif // CORES_CODES_THINCONTROLLER

#if CORES_CODES_THINWEBCLIENT
    // シンテレワークシステム HTML5 Web クライアントの動作をカスタマイズするためのクラスです。
    public class MyThinWebClientHook : ThinWebClientHookBase
    {
        // 接続要求に対する Rate Limiter の設定
        public override RateLimiter<string> GetRateLimiterForNewSession()
        {
            // デフォルト設定: 30 秒間で 10 回までバースト接続可能。それを超えた場合は、10 秒間に 1 回の割合まで接続可能。
            return new RateLimiter<string>(
                new RateLimiterOptions(
                    burst: 10.0,
                    limitPerSecond: 0.1,
                    expiresMsec: 30 * 1000,
                    mode: RateLimiterMode.NoPenalty
                    )
                );;
        }

        // 中継ゲートウェイと同一のプロトコル透かし (バイナリデータ) の取得
        public override ReadOnlyMemory<byte> GetProtocolWatermarkBinary()
        {
            // 中継ゲートウェイと同一のプロトコル透かし (バイナリデータ) を変更したい場合は、
            // 「ThinWebClient_ProtocolWatermark/ThinWebClient_ProtocolWatermark.txt」 ファイルの内容を変更するか、または、別のファイルを以下の行で参照すること。
            // 詳しくは、「Vars/VarResources/VarResources/ThinWebClient_ProtocolWatermark/README.txt」ファイルの説明を参照すること。
            return Str.CHexArrayToBinary(AppGlobal.AppRes["ThinWebClient_ProtocolWatermark/ThinWebClient_ProtocolWatermark.txt"].String);
        }
    }
#endif // CORES_CODES_THINWEBCLIENT

    /// --- 以下のコードは変更しないでください ---
    /// 
    // 内部ヘルパー
    public static class _AppLibHelper
    {
        public static readonly string AppThisSourceCodeFileName = Dbg.GetCallerSourceCodeFilePath();
    }

    // 内部ヘルパー
    public static partial class AppGlobal
    {
        public static ResourceFileSystem AppRes => Res.Codes;

        public static partial class Res
        {
            public static readonly ResourceFileSystem Codes = ResourceFileSystem.CreateOrGet(
                new AssemblyWithSourceInfo(typeof(Res), new SourceCodePathAndMarkerFileName(_AppLibHelper.AppThisSourceCodeFileName, "app_resource_root")));
        }
    }
}

