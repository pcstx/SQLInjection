using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Text.RegularExpressions;
using System.IO;

namespace SQLInjection
{
    /// <summary>
    /// 通过正则匹配来过滤
    /// </summary>
    public class CheckSQLReg
    {
        public static void Check(HttpApplication application, SQLInjectionParam param)
        {
            HttpContext context = application.Context;
            HttpRequest request = context.Request;
            string file = "";

            #region 记录日志文件

            if (param.SQLInjectionType % 2 == 1) //记录到日志
            {
                try
                {
                    file = context.Server.MapPath(param.SQLInjectionLogFile);
                    FileInfo fi = new FileInfo(file);
                    if (!fi.Exists)
                    {
                        Directory.CreateDirectory(fi.DirectoryName);
                    }
                }
                catch
                {
                }
            }
            #endregion


            // -----------------------防 Post 注入-----------------------
            if (request.Form != null)
            {
                for (int k = 0; k < request.Form.Count; k++)
                {
                    string getsqlkey = request.Form.Keys[k];
                    string formValue = request.Form[getsqlkey].ToLower();
                    Find(request, getsqlkey, formValue, (int)CheckItem.form, param.SQLInjectionLevel, param.SQLInjectionType, file);
                }
            }
            // -----------------------防 GET 注入-----------------------
            if (request.QueryString != null)
            {
                for (int k = 0; k < request.QueryString.Count; k++)
                {
                    string getsqlkey = request.QueryString.Keys[k];
                    string queryValue = request.QueryString[getsqlkey].ToLower();
                    Find(request, getsqlkey, queryValue, (int)CheckItem.query, param.SQLInjectionLevel, param.SQLInjectionType, file);
                }
            }
            // -----------------------防 Cookies 注入-----------------------
            if (request.Cookies != null)
            {
                for (int k = 0; k < request.Cookies.Count; k++)
                {
                    string getsqlkey = request.Cookies.Keys[k];
                    string cookieValue = request.Cookies[getsqlkey].Value.ToLower();
                    Find(request, getsqlkey, cookieValue, (int)CheckItem.cookie, param.SQLInjectionLevel, param.SQLInjectionType, file);
                }
            }
        }

        public static void Find(HttpRequest request, string key, string value, int type, int level, int SQLInjectionType, string fileName)
        {
            string getip = "";
            string optionType = "";
            switch (type)
            {
                case (int)CheckItem.form:
                    optionType = "Form ";
                    break;
                case (int)CheckItem.query:
                    optionType = "Query ";
                    break;
                case (int)CheckItem.cookie:
                    optionType = "Cookie ";
                    break;
            }

            bool isInjection = false;
            string keyword = "";

            string reg1 = @"'|<[^>]+?style=[\w]+?:expression\(|<[^>]*?=[^>]*?&#[^>]*?>|\b(alert|confirm|prompt)\b|^\+/v(8|9)|\bonmouse(over|move)=\b|\b(and|or)\b.+?(>|<|=|\bin\b|\blike\b)|/\*.+?\*/|<\s*script\b|\bEXEC\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE)";
            string reg2 = @"'|\b(and|or)\b.+?(>|<|=|\bin\b|\blike\b)|/\*.+?\*/|<\s*script\b|\bEXEC\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE)";
            string reg3 = @"\b(and|or)\b.{1,6}?(=|>|<|\bin\b|\blike\b)|/\*.+?\*/|<\s*script\b|\bEXEC\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE)";
            string reg4 = @"<[^>]+?style=[\w]+?:expression\(|\bonmouse(over|move)=\b|\b(alert|confirm|prompt)\b|^\+/v(8|9)|<[^>]*?=[^>]*?&#[^>]*?>|\b(and|or)\b.{1,6}?(=|>|<|\bin\b|\blike\b)|/\*.+?\*/|<\s*script\b|<\s*img\b|\bEXEC\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE)";

            isInjection = RegMath(reg1, value, out keyword);
            if (!isInjection)
            {
                isInjection = RegMath(reg2, value, out keyword);

                if (!isInjection)
                {
                    isInjection = RegMath(reg3, value, out keyword);

                    if (!isInjection)
                    {
                        isInjection = RegMath(reg4, value, out keyword);
                    }
                }
            }

            if (isInjection)
            {
                #region 页面输出
                HttpContext.Current.Response.Write("<script>alert('防注入程序提示您，" + keyword + " 为非法字符请删除后再提交！');</" + "script>");
                HttpContext.Current.Response.Write("<h3>您提交的数据中存在非法的字符，请删除后再提交</h3>");

                HttpContext.Current.Response.Write("非 法 字 符：<span style='color:#f60'>" + keyword + "</span><br>");
                HttpContext.Current.Response.Write("提 交 参 数：" + key + "<br>");
                HttpContext.Current.Response.Write("提 交 方 式：" + optionType + "<br>");
                HttpContext.Current.Response.Write("操 作 页 面：" + request.ServerVariables["URL"] + "<br>");
                HttpContext.Current.Response.Write("操 作 I P ：" + getip + "<br>");
                HttpContext.Current.Response.Write("操 作 时 间：" + DateTime.Now.ToString() + "<br>");
                value = value.Replace(keyword, "<span style='color:#f60'>" + keyword + "</span>");
                HttpContext.Current.Response.Write("提 交 数 据：" + value + "<br>");
                HttpContext.Current.Response.End();
                #endregion
            }

        }

        private static bool RegMath(string regStr, string value, out string resultValue)
        {
            bool isInjection = false;
            Regex r1 = new Regex(regStr.ToLower());

            Match m = r1.Match(value);
            if (m.Success)
            {
                isInjection = true;
                resultValue = m.Value;
            }
            else
            {
                resultValue = "";
            }

            return isInjection;
        }

        private enum CheckItem : int
        {
            form = 1,
            query,
            cookie
        }
         
    }
}
