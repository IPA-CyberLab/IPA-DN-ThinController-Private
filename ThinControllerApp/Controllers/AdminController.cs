using System;
using System.Buffers;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Net;
using System.Net.Sockets;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;


using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using IPA.Cores.Basic;
using IPA.Cores.Helper.Basic;
using static IPA.Cores.Globals.Basic;

using IPA.Cores.Codes;
using IPA.Cores.Helper.Codes;
using static IPA.Cores.Globals.Codes;

using IPA.Cores.Web;
using IPA.Cores.Helper.Web;
using static IPA.Cores.Globals.Web;

using IPA.App.ThinControllerApp.Models;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;

namespace IPA.App.ThinControllerApp.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        readonly ThinController Controller;

        public AdminController(ILogger<HomeController> logger, ThinController controller)
        {
            _logger = logger;
            this.Controller = controller;

            this.Controller.Db.StartLoop();
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Vars()
        {
            return View();
        }

        public IActionResult Servers()
        {
            return View();
        }

        public IActionResult Sessions()
        {
            return View();
        }

        public IActionResult Stat()
        {
            return View();
        }

        public IActionResult Reboot(string? subnets, string? when)
        {
            subnets = subnets._NonNull();
            when = when._NonNull();

            ViewBag.Ok = false;

            string error = "";

            if (this._IsPostBack())
            {
                if (subnets._IsEmpty())
                {
                    error = "サブネット一覧が指定されていません。";
                }
                else
                {
                    int secs = 0;
                    DateTime dt = ZeroDateTimeValue;

                    if (when._IsFilled())
                    {
                        if (when._IsNumber())
                        {
                            secs = when._ToInt();
                            if (secs < 10 || secs > 86400)
                            {
                                error = "秒数が許容範囲外です。";
                            }
                        }

                        if (secs == 0)
                        {
                            try
                            {
                                dt = when._ToDateTime(false, true);
                            }
                            catch
                            {
                                error = "日時指定が不正です。";
                            }

                            if (dt._IsZeroDateTime())
                            {
                                error = "日時指定が不正です。";
                            }
                        }
                        else
                        {
                            dt = DtNow.AddSeconds(secs);
                        }
                    }
                    else
                    {
                        dt = Util.MaxDateTimeValue;
                    }

                    var acl = EasyIpAcl.GetOrCreateCachedIpAcl(subnets, EasyIpAclAction.Deny, EasyIpAclAction.Deny);
                    if (acl.RuleList.Any() == false)
                    {
                        error = "IP アドレスのルールが 1 つも正しく指定されていません。";
                    }
                    else
                    {
                        int ret = this.Controller.SessionManager.UpdateNextRebootTime(acl, dt);

                        error = $"{ret} 個の中継ゲートウェイの再起動時刻を {dt._AsDateTimeOffset(true, true)._ToDtStr(zeroDateTimeStr: "「解除」")} に設定しました。結果は、「ゲートウェイ一覧」から表示できます。";
                        ViewBag.Ok = true;
                    }
                }
            }

            ViewBag.Subnets = subnets;
            ViewBag.When = when;
            ViewBag.ErrorStr = error;

            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
