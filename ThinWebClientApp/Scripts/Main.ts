// --- CSS ---
require("./Main.scss");

// --- Polyfill ---
require("./submodules/IPA-DN-WebNeko/Scripts/Polyfill/polyfill.ts");

// --- HTML parts ---
import "core-js/es/promise";
import "@fortawesome/fontawesome-free/js/all";
import "prismjs";
import "prismjs/components/prism-json";
import "prismjs/components/prism-bash";
import "prismjs/plugins/line-numbers/prism-line-numbers";
import "prismjs/plugins/autolinker/prism-autolinker";
import "prismjs/plugins/command-line/prism-command-line";
import "prismjs/plugins/normalize-whitespace/prism-normalize-whitespace";
import "buefy";

// --- Imports ---
import { default as Guacamole } from "./submodules/IPA-DN-WebNeko/Libraries/guacamole-common-js-1.3.0/guacamole-common";
import { Util } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Util";
import { Str } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Str";
import { GuaComfortableKeyboard, GuaConnectedKeyboard, GuaKeyCodes, GuaUtil, GuaStates, GuaConsts, GuaResizeManager } from "./submodules/IPA-DN-WebNeko/Scripts/Misc/GuaUtil/GuaUtil";
import { ClipboardUtil, Html } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Html";
import { Secure } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Secure";
import { Task } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Task";
import { Axios, Vue, Buefy } from "./submodules/IPA-DN-WebNeko/Scripts/Imports";
import { Time } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Time";
import { PageContext, StrTable, StrTableUtil } from "./submodules/IPA-DN-WebNeko/Scripts/Common/Base/Cores";

// --- Common Init ---
Vue.use(Buefy);

let Page: PageContext;
let Stb: StrTable;

// ページを初期化 (各ページで共通)
export function Cores_InitJavaScriptWithPageContext(contextObjStr: string): void
{
    const contextObj = Util.JsonToObject(Str.JavaScriptSafeStrDecode(contextObjStr));

    Page = new PageContext(contextObj);
    Stb = StrTableUtil.LoadStrTable(Page.LanguageKey);
}

// メイン画面の PCID のテキストが更新されるなど、状態がアップデートされた
export function Index_UpdateControl(page: Document): void
{
    let ok = false;

    let ok_wol = false;

    const pcid = page.getElementById("CurrentProfile_Pcid") as HTMLInputElement;
    const button1 = page.getElementById("ok1") as HTMLInputElement;
    const button2 = page.getElementById("ok2") as HTMLInputElement;
    const button_wol = page.getElementById("button_wol") as HTMLInputElement;
    const wol_target_pcid = page.getElementById("WoLTargetPcid") as HTMLInputElement;
    const wol_trigger_pcid = page.getElementById("CurrentProfile_Preference_WoLTriggerPcid") as HTMLInputElement;

    if (Str.IsFilled(pcid.value))
    {
        ok = true;
    }

    wol_target_pcid.value = Str.NonNullTrim(pcid.value);

    if (ok && Str.IsFilled(wol_trigger_pcid.value))
    {
        ok_wol = true;
    }

    button1.disabled = !ok;
    button2.disabled = !ok;

    button_wol.disabled = !ok_wol;

    const screenWidth = page.getElementById("CurrentProfile_Preference_ScreenWidth") as HTMLInputElement;
    const screenHeight = page.getElementById("CurrentProfile_Preference_ScreenHeight") as HTMLInputElement;
    const screenAutoCheckBox = page.getElementById("ScreenGetAutoSize") as HTMLInputElement;

    const currentScreenSize = Html.GetFullScreenSize();

    if (screenAutoCheckBox.checked)
    {
        screenWidth.value = currentScreenSize[0].toString();
        screenHeight.value = currentScreenSize[1].toString();

        screenWidth.readOnly = true;
        screenHeight.readOnly = true;

        screenWidth.style.backgroundColor = "whitesmoke";
        screenHeight.style.backgroundColor = "whitesmoke";
    }
    else
    {
        screenWidth.readOnly = false;
        screenHeight.readOnly = false;

        screenWidth.style.backgroundColor = "white";
        screenHeight.style.backgroundColor = "white";
    }
}

// メイン画面の接続履歴候補の選択が変更された
export function Index_OnSelectedHistoryChange(page: Document): void
{
    const dropdown = page.getElementById("SelectedHistory") as HTMLSelectElement;
    const pcid = page.getElementById("CurrentProfile_Pcid") as HTMLInputElement;
    const username = page.getElementById("CurrentProfile_Preference_Username") as HTMLInputElement;
    const password = page.getElementById("CurrentProfile_Preference_Password") as HTMLInputElement;
    const domain = page.getElementById("CurrentProfile_Preference_Domain") as HTMLInputElement;

    if (Str.IsFilled(dropdown.value))
    {
        // 何か選択されている状態に変化した。
        Html.NativateTo(dropdown.value);
    }
    else
    {
        // 何も選択されてていない状態になった。コンピュータ ID 入力 BOX をクリアしてフォーカスを移動する。
        username.value = "";
        password.value = "";
        domain.value = "";
        pcid.value = "";
        pcid.focus();
    }

    Index_UpdateControl(page);
}

// メイン画面がロードされた
export function Index_Load(page: Document, focusPcid: boolean, passwordEasyStrEncrypted: string, wolErrorMessage: string, wolOkMessage: string, jumpToWol: boolean): void
{
    if (Str.IsSamei(Html.GetBrowserType(), "ie"))
    {
        const ie_warning = page.getElementById("ie_warning");
        ie_warning!.hidden = false;
    }

    const password = page.getElementById("CurrentProfile_Preference_Password") as HTMLInputElement;
    const pcid = page.getElementById("CurrentProfile_Pcid") as HTMLInputElement;

    const wol_target_pcid = page.getElementById("WoLTargetPcid") as HTMLInputElement;
    const wol_trigger_pcid = page.getElementById("CurrentProfile_Preference_WoLTriggerPcid") as HTMLInputElement;

    wolErrorMessage = Str.JavaScriptSafeStrDecode(wolErrorMessage);
    wolOkMessage = Str.JavaScriptSafeStrDecode(wolOkMessage);

    wol_target_pcid.readOnly = true;

    if (focusPcid)
    {
        Html.FocusEx(pcid);
    }

    // 画面のパスワード入力テキストボックスのパスワードを入力する
    const passwordStr = Secure.JavaScriptEasyStrDecrypt(passwordEasyStrEncrypted, "easyEncryptStaticKey");

    password.value = passwordStr;

    Index_UpdateControl(page);

    Task.StartAsyncTaskAsync(async function () 
    {
        // WoL エラーまたは WoL OK が発生している場合はエラーメッセージを表示する
        if (Str.IsFilled(wolErrorMessage))
        {
            await Html.DialogAlertAsync(wolErrorMessage, Stb["THINWEB_JS_WOL_ERROR"], false, "is-info", "fas fa-exclamation-triangle", undefined, true);
        }

        if (Str.IsFilled(wolOkMessage))
        {
            await Html.DialogAlertAsync(wolOkMessage, "THINWEB_JS_WOL_OK", false, "is-primary", "fas fa-power-off", undefined, false);
        }
    }, false);

    if (jumpToWol)
    {
        // WoL の部分にジャンプする
        window.location.hash = "#wol";
    }

    // Webp サポートの有無の検出 (非同期処理が必要)
    Task.StartAsyncTaskAsync(async function ()
    {
        const isWebpSuppported = await Html.IsWebpSupportedAsync();
        const isWebpSuppported_formvalue = page.getElementById("IsWebpSupported") as HTMLInputElement;
        isWebpSuppported_formvalue.value = Str.ToStr(isWebpSuppported);
    });
}

// OTP 画面がロードされた
export function SessionOtp_Load(page: Document): void
{
    const otp = page.getElementById("otp") as HTMLInputElement;

    // OTP 入力欄をフォーカスする
    otp.focus();
}

// 高度な認証認証画面がロードされた
export function SessionAuthAdvanced_Load(page: Document): void
{
    const username = page.getElementById("username") as HTMLInputElement;
    const password = page.getElementById("password") as HTMLInputElement;

    // ユーザー名入力欄をフォーカスする
    username.focus();
}

// パスワード認証画面がロードされた
export function SessionAuthPassword_Load(page: Document): void
{
    const pcid = page.getElementById("Profile_Pcid") as HTMLInputElement;
    const password = page.getElementById("password") as HTMLInputElement;

    // PCID 入力欄を読み取り専用にする
    pcid.readOnly = true;
    pcid.style.backgroundColor = "whitesmoke";

    // パスワード入力欄をフォーカスする
    password.focus();
}

// 接続履歴の消去ボタンがクリックされた
export function Index_DeleteAllHistory(page: Document): void
{
    Task.StartAsyncTaskAsync(async function () 
    {
        if (await Html.DialogConfirmAsync(Stb["THINWEB_JS_ERASE"], Stb["THINWEB_JS_ERASE2"], false, "is-primary", undefined, false, Stb["THINWEB_JS_YES"], Stb["THINWEB_JS_NO"]))
        {
            Html.NativateTo("/?deleteall=1");
        }
    }, false);
}

// 1 秒に 1 回 KeepAlive URL を呼び出す
async function SendHeartBeatAsync(url: string): Promise<void>
{
    while (true)
    {
        try
        {
            const response = await Axios.get(url, { timeout: 1000 });
        }
        catch (ex)
        {
            Util.Debug("Error get " + ex);
        }

        await Task.Delay(1000);
    }
}

// 1 秒に 1 回 KeepAlive URL を呼び出す処理を開始する
export function Common_StartSendHeartBeat(sessionId: string, requestId: string): void
{
    sessionId = Str.NonNullTrim(sessionId);
    requestId = Str.NonNullTrim(requestId);

    const url = `/ThinWebClient/SendHeartBeat/?sessionId=${sessionId}&requestId=${requestId}`;
    Task.StartAsyncTaskAsync(SendHeartBeatAsync(url));
}

// 1 秒に 1 回 HealthCheck URL を呼び出し、セッションが終了していることを検出したらメッセージを出して終了する
async function SessionHealthCheckAsync(url: string, pcid?: string): Promise<void>
{
    while (true)
    {
        try
        {
            const response = await Axios.get(url, { timeout: 1000 });
            const str = response.data as string;

            if (!Str.ToBool(str))
            {
                // セッション消滅のエラー等が発生した模様である
                await Remote_ShowDisconnectErrorAsync(pcid);

                // もうループは抜けます！ ずるっこ！！
                break;
            }
        }
        catch (ex)
        {
            // 通信エラーは無視する
            Util.Debug("Error get " + ex);
        }

        await Task.Delay(1000);
    }
}

let Remote_ErrorShowOnceFlag = false;

// セッションが終了した旨のエラーメッセージを表示する (1 回しか表示されない)
async function Remote_ShowDisconnectErrorAsync(pcid?: string): Promise<void>
{
    // 1 回しかエラーが表示されないようにする
    if (Remote_ErrorShowOnceFlag)
    {
        return;
    }

    Remote_ErrorShowOnceFlag = true;

    await Html.DialogAlertAsync(Stb["THINWEB_JS_REMOTE_FINISH"], Stb["THINWEB_JS_REMOTE_FINISH_TITLE"], true, "is-success", "fas fa-info-circle");

    let gotoUrl = "/";
    if (Str.IsFilled(pcid))
    {
        gotoUrl += "?pcid=" + Str.EncodeUrl(pcid?.trim());
    }
    Html.NativateTo(gotoUrl);
}

// 1 秒に 1 回 HealthCheck URL を呼び出す処理を開始する
export function Remote_StartSessionHealthCheck(sessionId: string, pcid?: string): void
{
    sessionId = Str.NonNullTrim(sessionId);

    const url = `/ThinWebClient/SessionHealthCheck/?sessionId=${sessionId}`;
    Task.StartAsyncTaskAsync(SessionHealthCheckAsync(url, pcid));
}

export function Common_ErrorAlert(page: Document, errorMessage: string, pcid?: string, title?: string, buttonColor = "is-danger", icon = "fas fa-exclamation-triangle"): void
{
    // 1 回しかエラーが表示されないようにする
    if (Remote_ErrorShowOnceFlag)
    {
        return;
    }

    if (Str.IsEmpty(title))
    {
        title = Stb["THINWEB_JS_ERROR1"];
    }

    Remote_ErrorShowOnceFlag = true;

    if (Str.IsEmpty(errorMessage))
    {
        errorMessage = Stb["THINWEB_JS_ERROR2"];
    }

    Task.StartAsyncTaskAsync(async function () 
    {
        await Html.DialogAlertAsync(errorMessage, title, true, buttonColor, icon);

        let url = "/";
        if (Str.IsFilled(pcid))
        {
            url += "?pcid=" + Str.EncodeUrl(pcid?.trim());
        }
        Html.NativateTo(url);
    }, false);
}

let Remote_ShowImeWarningFlag = false;

export async function Remote_ShowImeWarningAsync(): Promise<void>
{
    if (Remote_ErrorShowOnceFlag)
    {
        // 何かエラーが発生しておる
        return;
    }

    if (Remote_ShowImeWarningFlag)
    {
        return;
    }

    Remote_ShowImeWarningFlag = true;

    try
    {
        await Html.DialogAlertAsync(Stb["THINWEB_JS_IME1"], Stb["THINWEB_JS_IME2"], true, "is-info", "far fa-keyboard");
    }
    finally
    {
        Remote_ShowImeWarningFlag = false;
    }
}

export function ThinWebClient_Error_PageLoad(window: Window, page: Document, message: string, title: string, redirectUrl: string, allowHtml = false, icon = "fas fa-exclamation-triangle"): void
{
    message = Str.JavaScriptSafeStrDecode(message);
    redirectUrl = Str.JavaScriptSafeStrDecode(redirectUrl);
    title = Str.JavaScriptSafeStrDecode(title);

    Task.StartAsyncTaskAsync(async function () 
    {
        if (await Html.DialogConfirmAsync(message, title, allowHtml, "is-info", icon, true, Stb["THINWEB_JS_OK"], Stb["THINWEB_JS_DETAIL"], true))
        {
            Html.NativateTo(redirectUrl);
        }
    }, false);
}


export function ThinWebClient_Remote_PageLoad(window: Window, page: Document, webSocketUrl: string,
    sessionId: string, pcid: string, svcType: string, jsonEncrypted: string, connectPacketData: string,
    watermarkStr1: string, watermarkStr2: string, miscJsonObj: string, misc2JsonObj: string): void
{
    const misc = Util.JsonToObject(Str.JavaScriptSafeStrDecode(miscJsonObj));
    const misc2 = Util.JsonToObject(Str.JavaScriptSafeStrDecode(misc2JsonObj));
    const profile = Util.JsonToObject(Secure.JavaScriptEasyStrDecrypt(jsonEncrypted, "easyJsonEncode"));
    const pref = profile.Preference;
    const isDebug = pref.EnableDebug as boolean;
    const display = page.getElementById("display")!;

    let enableClipboardC2S: boolean = pref.EnableClipboardC2S;
    let enableClipboardS2C: boolean = pref.EnableClipboardS2C;
    let enableClipboard = enableClipboardC2S || enableClipboardS2C;
    let enableMic = pref.EnableMic;

    if (misc.IsShareDisabled)
    {
        enableClipboardC2S = enableClipboardS2C = enableClipboard = false;
    }

    if (!misc.IsAudioInSupported)
    {
        enableMic = false;
    }

    // 高速化のまじない (効かないかも)
    function window_animate_callback(timestamp: number): void
    {
        window.requestAnimationFrame(window_animate_callback);
    }
    window.requestAnimationFrame(window_animate_callback);

    let userInputOccured = false;

    if (pref.ScreenAutoResize)
    {
        // 自動リサイズが有効の場合、初期ウインドウサイズを現在のウインドウサイズで上書きする
        let width = Math.min(Math.max(window.innerWidth, GuaConsts.MinWidth), GuaConsts.MaxWidth);
        let height = Math.min(Math.max(window.innerHeight, GuaConsts.MinHeight), GuaConsts.MaxHeight);

        // ただし自動フルスクリーンが ON の場合は、フルスクリーンサイズで上書きする
        if (pref.ScreenAutoFullScreen)
        {
            const fullScreenSize = Html.GetFullScreenSize();
            width = fullScreenSize[0];
            height = fullScreenSize[1];
        }

        pref.ScreenWidth = width;
        pref.ScreenHeight = height;
    }

    if (!pref.ShowLocalMouseCursor)
    {
        display.style.cursor = "none";
    }

    display.style.width = pref.ScreenWidth + "px";
    display.style.height = pref.ScreenHeight + "px";

    pcid = Str.JavaScriptSafeStrDecode(pcid);
    connectPacketData = Str.JavaScriptSafeStrDecode(connectPacketData);

    watermarkStr1 = Str.JavaScriptSafeStrDecode(watermarkStr1);
    watermarkStr2 = Str.JavaScriptSafeStrDecode(watermarkStr2);

    if (isDebug)
    {
        Util.Debug(`ThinWebClient_Remote_PageLoad: webSocketUrl = ${webSocketUrl}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: sessionId = ${sessionId}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: pcid = ${pcid}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: svcType = ${svcType}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: connectPacketData = ${connectPacketData}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: profile = ${Util.ObjectToJson(profile)}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: watermarkStr1 = ${watermarkStr1}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: watermarkStr2 = ${watermarkStr2}`);
        Util.Debug(`ThinWebClient_Remote_PageLoad: misc = ${Util.ObjectToJson(misc)}`);
    }

    if (Str.IsEmpty(connectPacketData))
    {
        // セッションヘルスチェックは WebSocket で ThinGate と直接対話するモードの場合は行なわない (ThinWebClient 的にはすでに何も状態を持っていないため)
        Remote_StartSessionHealthCheck(sessionId, pcid);
    }

    window.onerror = function (msg: any, url?: string, fileno?: number, linenumber?: number): any
    {
        const str = `Error message: ${msg}\nURL: ${url}\nLine Number: ${linenumber}`;

        if (isDebug) Util.Debug(str);
        Html.SetPreventPageUnload(false);
        Common_ErrorAlert(page, str, pcid);
        return true;
    }

    const tunnel = new Guacamole.WebSocketTunnel(webSocketUrl);

    // @ts-ignore
    tunnel.firstPacketData = connectPacketData;

    // @ts-ignore
    tunnel.onerror = function (status: Guacamole.Status): void
    {
        const code = status.code;
        let msg = status.message;
        const original = Stb["THINWEB_JS_INTERNAL_ERROR"];

        if (code === 519)
        {
            msg = Stb["THINWEB_JS_ERR_DISCON"] + "<BR><BR>" +
                original + msg;
        }
        else if (code === 514)
        {
            msg = Stb["THINWEB_JS_ERR_TIMEO"] + "<BR><BR>" +
                original + msg;
        }

        const str = `${Stb["THINWEB_JS_TUNNEL_ERROR_CODE"]}: ${code}, ${Stb["THINWEB_JS_ERR_MSG"]}:<BR>"${msg}"`;

        if (isDebug) Util.Debug(str);
        Html.SetPreventPageUnload(false);
        Common_ErrorAlert(page, str, pcid);
    };

    // Instantiate client, using a WebSocket tunnel for communications.
    const guac = new Guacamole.Client(tunnel);

    const guacDisplay = guac.getDisplay();

    const defaultLayer = guacDisplay.getDefaultLayer();

    if (Str.IsFilled(watermarkStr1) && Str.IsFilled(watermarkStr2))
    {
        // @ts-ignore
        defaultLayer.watermark_Text1 = watermarkStr1;
        // @ts-ignore
        defaultLayer.watermark_Text2 = watermarkStr2;
        // @ts-ignore
        defaultLayer.dn_is_draw_watermark = true;
    }

    // Add client to display div
    display.appendChild(guacDisplay.getElement());

    // Error handler
    // @ts-ignore
    guac.onerror = function (status: Guacamole.Status): void
    {
        const code = status.code;
        let msg = status.message;

        const original = Stb["THINWEB_JS_ORIGINAL_ERROR"];

        if (Str.InStr(msg, "See logs.", false))
        {
            msg = Stb["THINWEB_JS_RDP_ERR"];
        }
        else if (code === 519)
        {
            msg = Stb["THINWEB_JS_519"] +
                original + msg;
        }
        else if (code === 769)
        {
            msg = Stb["THINWEB_JS_769"] + "<BR><BR>" +
                original + msg;
        }

        const str = `${Stb["THINWEB_JS_RDP_ERROR_CODE"]}: ${code}, ${Stb["THINWEB_JS_ERR_MSG"]}:<BR>"${msg}"`;

        if (isDebug) Util.Debug(str);
        Html.SetPreventPageUnload(false);
        Common_ErrorAlert(page, str, pcid);
    };

    let onceMsgShowed = false;

    // From guacamole-client-1.3.0\guacamole\src\main\webapp\app\client\types\ManagedClient.js:323
    const requestAudioStream = (client: Guacamole.Client): void =>
    {
        if (enableMic)
        {
            try
            {
                // Create new audio stream, associating it with an AudioRecorder
                const mimeType = "audio/L16;rate=44100,channels=2";
                const stream = client.createAudioStream(mimeType);
                const recorder = Guacamole.AudioRecorder.getInstance(stream, mimeType);

                // If creation of the AudioRecorder failed, simply end the stream
                if (!recorder)
                {
                    stream.sendEnd();
                }
                // Otherwise, ensure that another audio stream is created after this
                // audio stream is closed
                else
                {
                    // @ts-ignore
                    recorder.onclose = requestAudioStream.bind(this, client);
                }
            }
            catch { }
        }
    };

    //const clipboardService = new GuacAppClipboardService(window);
    const clipboardUtil = new ClipboardUtil();

    // From guacamole-client-1.3.0\guacamole\src\main\webapp\app\index\controllers\indexController.js:153
    const checkClipboard = async function checkClipboard(): Promise<void>
    {
        if (enableClipboardC2S)
        {
            try
            {
                const data = await clipboardUtil.TryReadLocalClipboardAsync();

                if (Str.IsFilled(data))
                {
                    // From guacamole-client-1.3.0\guacamole\src\main\webapp\app\client\directives\guacClient.js:416
                    // From guacamole-client-1.3.0\guacamole\src\main\webapp\app\client\types\ManagedClient.js:707
                    // @ts-ignore
                    const stream = guac.createClipboardStream(data.Type);

                    const writer = new Guacamole.StringWriter(stream);
                    writer.sendText(data);
                    writer.sendEnd();

                    //console.log("sent");
                }
            }
            catch { }
        }
    };

    if (enableClipboardS2C)
    {
        // @ts-ignore
        guac.onclipboard = function clientClipboardReceived(stream: Guacamole.InputStream, mimetype: string): void
        {
            try
            {
                // From guacamole-client-1.3.0\guacamole\src\main\webapp\app\client\types\ManagedClient.js
                if (/^text\//.exec(mimetype))
                {
                    const reader = new Guacamole.StringReader(stream);

                    let data = "";

                    // @ts-ignore
                    reader.ontext = function textReceived(text: string): void
                    {
                        data += text;
                    };

                    // @ts-ignore
                    reader.onend = function textComplete(): void
                    {
                        //console.log("recv clip");
                        //console.log(data);

                        clipboardUtil.WriteLocalClipboardAsync(data);
                    };
                }
            }
            catch { }
        };
    }

    // @ts-ignore
    guac.onstatechange = function (state: GuaStates): void
    {
        if (isDebug)
        {
            Util.Debug(`guac.onstatechange: ${state}`);
        }

        if (state === GuaStates.STATE_DISCONNECTED || state === GuaStates.STATE_DISCONNECTING)
        {
            Html.SetPreventPageUnload(false);

            // 切断メッセージを表示
            Remote_ShowDisconnectErrorAsync(pcid);
        }
        else if (state === GuaStates.STATE_CONNECTED)
        {
            if (!onceMsgShowed)
            {
                onceMsgShowed = true;
                // 接続完了時にメッセージを表示する
                Task.StartAsyncTaskAsync(async function () 
                {
                    let onceMsg = Str.NonNull(misc2.OnceMsg);
                    const onceMsgTitle = Str.NonNull(misc2.OnceMsgTitle);

                    if (Str.IsFilled(onceMsg) && Str.IsFilled(onceMsgTitle))
                    {
                        if (pref.ShowOnceMsg)
                        {
                            onceMsg += "\r\n\r\n" + Stb["THINWEB_JS_MSG_HIDE"];

                            await Html.DialogAlertAsync(onceMsg, onceMsgTitle, false, "is-success is-light", "fas fa-info-circle");
                        }
                    }
                }, false);
            }

            if (enableMic)
            {
                requestAudioStream(guac);
            }

            if (enableClipboardC2S)
            {
                checkClipboard();
            }
        }
    };

    Html.SetPreventPageUnload(true);

    // Connect
    guac.connect(`id=${sessionId}&width=${pref.ScreenWidth}&height=${pref.ScreenHeight}`);

    // Disconnect on close
    window.onunload = function (): void
    {
        guac.disconnect();
    }

    // Clipboard
    if (enableClipboardC2S)
    {
        window.addEventListener("load", checkClipboard, true);
        window.addEventListener("copy", checkClipboard);
        window.addEventListener("cut", checkClipboard);
        window.addEventListener("focus", function focusGained(e)
        {
            if (e.target === window)
                checkClipboard();
        }, true);
    }

    // Mouse
    const mouse = new Guacamole.Mouse(guacDisplay.getElement());

    // @ts-ignore
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = function (mouseState: Guacamole.Mouse.State): void
    {
        userInputOccured = true;

        //Util.Debug(mouseState);
        const scale = guacDisplay.getScale();

        // Scale event by current scale
        const scaledState = new Guacamole.Mouse.State(
            mouseState.x / scale,
            mouseState.y / scale,
            mouseState.left,
            mouseState.middle,
            mouseState.right,
            mouseState.up,
            mouseState.down,
            // @ts-ignore
            mouseState.forward,
            // @ts-ignore
            mouseState.back);

        guac.sendMouseState(scaledState);
    };

    // Keyboard
    const keyboard = new Guacamole.Keyboard(page);

    const virtualKeyboard1 = new GuaConnectedKeyboard(guac, profile, svcType);
    const virtualKeyboard2 = new GuaComfortableKeyboard(virtualKeyboard1, profile, svcType);

    // @ts-ignore
    keyboard.onkeydown = function (keysym: number): void
    {
        virtualKeyboard2.PhysicalKeyPressedAsync(keysym, true);
    };

    // @ts-ignore
    keyboard.onkeyup = function (keysym: number): void
    {
        virtualKeyboard2.PhysicalKeyPressedAsync(keysym, false);
    };

    if (pref.ScreenAutoResize)
    {
        // 自動リサイズが有効の場合、スクロールバーは表示しない
        page.documentElement.style.overflowX = "hidden";
        page.documentElement.style.overflowY = "hidden";

        // @ts-ignore
        guacDisplay.onresize = function (): void
        {
            userInputOccured = true;

            // サーバーに接続した時点と、ユーザー側またはサーバー側が原因で画面サイズが変化した時点で呼ばれる
            const serverWidth = guacDisplay.getWidth();
            const serverHeight = guacDisplay.getHeight();

            // ユーザー指定のウインドウサイズを確認する
            const clientWidth = Math.min(Math.max(window.innerWidth, GuaConsts.MinWidth), GuaConsts.MaxWidth);
            const clientHeight = Math.min(Math.max(window.innerHeight, GuaConsts.MinHeight), GuaConsts.MaxHeight);

            // 適切な拡大縮小倍率を計算する
            const scale = Math.min(clientWidth / Math.max(serverWidth, 1), clientHeight / Math.max(serverHeight, 1));

            guacDisplay.scale(scale);

            // 中央配置する
            const childDiv = display.getElementsByTagName("div")[0];

            const divWidth = childDiv.clientWidth;
            const divHeight = childDiv.clientHeight;

            const divLeft = Math.max((clientWidth - divWidth) / 2, 0);
            const divTop = Math.max((clientHeight - divHeight) / 2, 0);

            childDiv.style.left = divLeft + "px";
            childDiv.style.top = divTop + "px";

            if (isDebug)
            {
                //                Util.Debug(`guacDisplay.onresize ${serverWidth} ${serverHeight}`);
                //                Util.Debug(`New scale = ${minScale}`);
            }

            // スクロールバー表示判断ルーチン
            scrollBarUpdateProc();
        };

        const resizeManager = new GuaResizeManager(guac, window.innerWidth, window.innerHeight);

        const isRezieDebug = false;

        if (!isRezieDebug)
        {
            // ユーザーがウインドウサイズを変更した
            window.onresize = function (ev: UIEvent): any
            {
                userInputOccured = true;

                const clientWidth = Math.min(Math.max(window.innerWidth, GuaConsts.MinWidth), GuaConsts.MaxWidth);
                const clientHeight = Math.min(Math.max(window.innerHeight, GuaConsts.MinHeight), GuaConsts.MaxHeight);

                display.style.width = clientWidth + "px";
                display.style.height = clientHeight + "px";

                if (pref.ScreenAutoResizeRemoteFit)
                {
                    // サーバーにサイズ変更を依頼する
                    resizeManager.Resize(clientWidth, clientHeight);
                }

                // @ts-ignore
                guacDisplay.onresize(); // 倍率の自動適用

                // スクロールバー表示判断ルーチン
                scrollBarUpdateProc();
            }
        }
        else
        {
            // リサイズバグを再現するためのデバッグ (ストレステスト)
            Task.StartAsyncTaskAsync(async function () 
            {
                while (false)
                {
                    await Task.Delay(Util.GetRandInt(300) + 10);

                    //console.log("aaa");
                    const clientWidth = Util.GetRandInt(500) + 1300;
                    const clientHeight = Util.GetRandInt(300) + 700;
                    display.style.width = clientWidth + "px";
                    display.style.height = clientHeight + "px";

                    if (pref.ScreenAutoResizeRemoteFit)
                    {
                        // サーバーにサイズ変更を依頼する
                        resizeManager.Resize(clientWidth, clientHeight, true);
                    }

                    // @ts-ignore
                    guacDisplay.onresize(); // 倍率の自動適用

                    // スクロールバー表示判断ルーチン
                    scrollBarUpdateProc();
                }
            }, false);

            // マウスを適当に動かす
            if (pref.ScreenAutoResizeRemoteFit)
            {
                Task.StartAsyncTaskAsync(async function () 
                {
                    while (true)
                    {
                        const count = Util.GetRandInt(100) + 1;

                        for (let i = 0; i < count; i++)
                        {
                            await Task.Delay(Util.GetRandInt(10) + 1);

                            try
                            {
                                const scale = guacDisplay.getScale();

                                const x = Util.GetRandInt(1300);
                                const y = Util.GetRandInt(700);

                                //console.log("" + x + " " + y);

                                // Scale event by current scale
                                const scaledState = new Guacamole.Mouse.State(
                                    x / scale,
                                    y / scale,
                                    false,
                                    false,
                                    false,
                                    false,
                                    false,
                                    // @ts-ignore
                                    false,
                                    // @ts-ignore
                                    false);

                                guac.sendMouseState(scaledState);
                            }
                            catch { }
                        }

                        await Task.Delay(Util.GetRandInt(500));

                    }
                }, false);
            }

            // キーボードを適当に押す
            if (pref.ScreenAutoResizeRemoteFit)
            {
                Task.StartAsyncTaskAsync(async function () 
                {
                    while (true)
                    {
                        await virtualKeyboard1.PhysicalKeyPressedAsync(GuaKeyCodes.Win, true);
                        await Task.Delay(Util.GetRandInt(512) + 256);

                        await virtualKeyboard1.PhysicalKeyPressedAsync(GuaKeyCodes.Win, false);
                        await Task.Delay(Util.GetRandInt(512) + 256);
                    }
                }, false);
            }
        }
    }
    else
    {
        // 自動リサイズが無効の場合

        // @ts-ignore
        guacDisplay.onresize = function (): void
        {
            userInputOccured = true;

            // サーバーに接続した時点と、サーバー側が原因で画面サイズが変化した時点で呼ばれる
            const serverWidth = guacDisplay.getWidth();
            const serverHeight = guacDisplay.getHeight();

            // 自動リサイズが無効の場合、初期ウインドウサイズを現在のリモートサイズで上書きする
            const width = Math.min(Math.max(serverWidth, GuaConsts.MinWidth), GuaConsts.MaxWidth);
            const height = Math.min(Math.max(serverHeight, GuaConsts.MinHeight), GuaConsts.MaxHeight);

            display.style.width = width + "px";
            display.style.height = height + "px";

            scrollBarUpdateProc();
        };

        // ユーザーがウインドウサイズを変更した
        window.onresize = function (ev: UIEvent): any
        {
            // スクロールバー表示判断ルーチン
            scrollBarUpdateProc();
        }
    }

    if (!pref.ShowRemoteMouseCursor)
    {
        guacDisplay.showCursor(false);
    }

    // オートリサイズ無効化時におけるスクロールバー表示判断ルーチン
    const scrollBarUpdateProc = (): void =>
    {
        const childDiv = display.getElementsByTagName("div")[0];

        const divWidth = childDiv.clientWidth;
        const divHeight = childDiv.clientHeight;

        const clientWidth = window.innerWidth;
        const clientHeight = window.innerHeight;

        page.documentElement.style.overflowX = divWidth > clientWidth ? "auto" : "hidden";
        page.documentElement.style.overflowY = divHeight > clientHeight ? "auto" : "hidden";
    };

    const fullScreenChangeProc = (): void =>
    {
        const isFullScreen = document.fullscreenElement ? true : false;

        // スクロールバーを表示するかどうかの判断ルーチン
        scrollBarUpdateProc();
    };

    let fullScreenUnsetOnceFlag = false;

    // フルスクリーン設定 / 解除が発生したときのイベント
    document.addEventListener("fullscreenchange", event =>
    {
        userInputOccured = true;

        fullScreenChangeProc();

        const isFullScreen = document.fullscreenElement ? true : false;
        if (!isFullScreen)
        {
            if (pref.ShowHelpOnFullScreenUnset)
            {
                if (pref.ScreenAutoFullScreen)
                {
                    if (autoFullScreenInitiated)
                    {
                        if (!fullScreenUnsetOnceFlag)
                        {
                            fullScreenUnsetOnceFlag = true;

                            // 自動フルスクリーンモードが ON のとき、初回にフルスクリーンが解除された場合はメッセージを出す
                            Task.StartAsyncTaskAsync(async function () 
                            {
                                const msg = Stb["THINWEB_JS_FULL_SCREEN_HINT"];

                                await Html.DialogAlertAsync(msg, "", true, "is-success is-light", "far fa-keyboard");
                            }, false);
                        }
                    }
                }
            }
        }
    });

    let autoFullScreenInitiated = false;

    document.addEventListener("keydown", event =>
    {
        userInputOccured = true;

        let showError = false;
        if (event.key.length >= 1)
        {
            const char = event.key[0];
            if (char >= 'ｱ' && char <= 'ﾝ')
            {
                // Chrome で、ローカルの IME が有効にされておるぞ
                Remote_ShowImeWarningAsync();
                showError = true;
            }
        }

        // 最初の 1 文字目を入力するときに、自動的にフルスクリーンにする
        if (!showError && !Remote_ErrorShowOnceFlag) // 何かエラーが発生しているときは表示しない
        {
            if (pref.ScreenAutoFullScreen)  // 自動フルスクリーン
            {
                if (!autoFullScreenInitiated)
                {
                    autoFullScreenInitiated = true;

                    // フルスクリーンになっていなければ、フルスクリーンにする
                    Task.StartAsyncTaskAsync(async () =>
                    {
                        if (Html.IsFullScreenSupported())
                        {
                            if (page.fullscreenElement === null)
                            {
                                await page.body.requestFullscreen();
                            }
                        }
                    });
                }
            }
        }
    });

    fullScreenChangeProc();

    // アイドルタイムアウト等の実装
    if (true)
    {
        const idleTimeout: number = misc.IdleTimeout;
        const lifetime: number = misc.LifeTime;
        let lifetimeMsg: string = misc.LifeTimeMsg;
        lifetimeMsg = Str.NonNull(lifetimeMsg);
        if (Str.IsEmpty(lifetimeMsg)) lifetimeMsg = `Disconnected by lifetime param ${lifetime}.`;

        if (idleTimeout !== 0)
        {
            Task.StartAsyncTaskAsync(async () =>
            {
                let lastInputTick = Time.Tick64;

                while (true)
                {
                    const now = Time.Tick64;

                    if (userInputOccured)
                    {
                        userInputOccured = false;
                        lastInputTick = now;
                    }
                    else
                    {
                        if (now > (lastInputTick + (idleTimeout * 1000)))
                        {
                            disconnectByTimeout(Str.EncodeHtml(
                                Str.ReplaceStr(Stb["THINWEB_JS_USER_TIMEOUT"], "__number__", Str.IntToStr(idleTimeout))));
                        }
                    }

                    await Task.Delay(256);
                }
            });
        }

        if (lifetime !== 0)
        {
            Task.StartAsyncTaskAsync(async () =>
            {
                await Task.Delay(lifetime);

                disconnectByTimeout(Str.EncodeHtml(lifetimeMsg));
            });
        }

        let disconnectedFlagByTimeout = false;

        const disconnectByTimeout = (msg: string): void =>
        {
            if (!disconnectedFlagByTimeout)
            {
                disconnectedFlagByTimeout = true;

                Common_ErrorAlert(page, msg, pcid, Stb["THINWEB_JS_TIMEOUT"], "is-primary", "far fa-clock");

                try
                {
                    guac.disconnect();
                }
                catch (ex)
                {
                    Util.Debug(ex);
                }
            }
        };
    };
}




