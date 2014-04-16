using System;
using System.Collections.Generic; 
using System.Text;
using System.Web;
using System.Text.RegularExpressions;

namespace SQLInjection
{
    public class CheckSQL
    {
       
        public static void Check(HttpApplication application,string keywords,int level)
        {
            HttpContext context = application.Context;
            HttpRequest request = context.Request;

            string sqlkeywords = "exec↓select↓drop↓alter↓exists↓union↓and↓or↓xor↓order↓mid↓asc↓execute↓xp_cmdshell↓insert↓update↓delete↓join↓declare↓char↓sp_oacreate↓wscript.shell↓xp_regwrite↓'↓;↓--";
 
            if (!string.IsNullOrEmpty(keywords))
            {
                if(keywords.StartsWith("↓"))
                {
                    sqlkeywords += keywords;
                }
                else
                {
                    sqlkeywords += "↓" + keywords;
                } 
            }

            //Stopwatch watch = new Stopwatch();
            //watch.Start();
            string[] sqlkeyword = sqlkeywords.Split('↓');
            foreach (string keyword in sqlkeyword)
            {
                // -----------------------防 Post 注入-----------------------
                if (request.Form!= null)
                {
                    for (int k = 0; k <request.Form.Count; k++)
                    {
                        string getsqlkey = request.Form.Keys[k];
                        string formValue= request.Form[getsqlkey].ToLower();
                        string getip = Find(request, keyword,getsqlkey, formValue, (int)CheckItem.form,level);
                    }
                }
                // -----------------------防 GET 注入-----------------------
                if (request.QueryString != null)
                {
                    for (int k = 0; k <request.QueryString.Count; k++)
                    {
                        string getsqlkey = request.QueryString.Keys[k];
                        string queryValue=request.QueryString[getsqlkey].ToLower();
                        string getip = Find(request, keyword, getsqlkey, queryValue, (int)CheckItem.query,level);
                    }
                }
                // -----------------------防 Cookies 注入-----------------------
                if (request.Cookies != null)
                {
                    for (int k = 0; k < request.Cookies.Count; k++)
                    {
                        string getsqlkey = request.Cookies.Keys[k];
                        string cookieValue=request.Cookies[getsqlkey].Value.ToLower();
                        string getip = Find(request, keyword,getsqlkey, cookieValue, (int)CheckItem.cookie,level);
                    }
                }
            }
            //watch.Stop();
            //TimeSpan ts = watch.Elapsed;
            //string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
            //    ts.Hours, ts.Minutes, ts.Seconds,
            //    ts.Milliseconds / 10);
            //System.Web.HttpContext.Current.Response.Write(elapsedTime);
            //System.Web.HttpContext.Current.Response.End();
        }

        private static string Find(HttpRequest request, string keyword,string key, string value,int type,int level)
        {
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

            string getip = "";
            string requestvalues = Regex.Replace(value, "\\s+", " ");
            string[] values = requestvalues.Split(' ');
            for (int i = 0; i < values.Length; i++)
            {                
                if (((level==1)&&Regex.Matches(values[i], keyword).Count > 0)||(level==0&&values[i]==keyword))
                {
                    HttpContext.Current.Response.Write("<script Language=JavaScript>alert('防注入程序提示您，请勿提交非法字符！');</" + "script>");
                    HttpContext.Current.Response.Write("非法操作！您存在非法的sql注入" + "<br>");
                    if (request.ServerVariables["HTTP_X_FORWARDED_FOR"] != null)
                    {
                        getip = request.ServerVariables["HTTP_X_FORWARDED_FOR"];
                    }
                    else
                    {
                        getip = request.ServerVariables["REMOTE_ADDR"];
                    }
                    HttpContext.Current.Response.Write("操 作 I P ：" + getip + "<br>");
                    HttpContext.Current.Response.Write("操 作 时 间：" + DateTime.Now.ToString() + "<br>");
                    HttpContext.Current.Response.Write("操 作 页 面：" + request.ServerVariables["URL"] + "<br>");
                    HttpContext.Current.Response.Write("提 交 方 式：" + optionType + "<br>");
                    HttpContext.Current.Response.Write("提 交 参 数：" + key + "<br>");
                    HttpContext.Current.Response.Write("提 交 数 据：" + value + "<br>");
                    HttpContext.Current.Response.End();
              }
            }
            return getip;
        }

        private enum CheckItem:int
        { 
            form=1,
            query,
            cookie            
        }

    }
}
