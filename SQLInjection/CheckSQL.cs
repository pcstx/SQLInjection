using System;
using System.Collections.Generic; 
using System.Text;
using System.Web;
using System.Text.RegularExpressions;
using System.Configuration;
using System.IO;

namespace SQLInjection
{
    public class CheckSQL
    {

        public static void Check(HttpApplication application, SQLInjectionParam param )
        {
            HttpContext context = application.Context;
            HttpRequest request = context.Request;

            string sqlkeywords = "select↓insert↓update↓delete↓drop↓create↓truncate↓join↓declare↓exists↓union↓and↓or↓xor↓order↓exec↓execute↓alter↓mid↓xp_cmdshell↓char↓sp_oacreate↓wscript.shell↓xp_regwrite";
           
            string file = "";

            if (!string.IsNullOrEmpty(param.SQLInjection))
            {
                if (param.SQLInjection.StartsWith("↓"))
                {
                    sqlkeywords += param.SQLInjection;
                }
                else
                {
                    sqlkeywords += "↓" + param.SQLInjection;
                }
            }

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
                        string getip = Find(request, keyword, getsqlkey, formValue, (int)CheckItem.form, param.SQLInjectionLevel, param.SQLInjectionType,  file);
                    }
                }
                // -----------------------防 GET 注入-----------------------
                if (request.QueryString != null)
                {
                    for (int k = 0; k <request.QueryString.Count; k++)
                    {
                        string getsqlkey = request.QueryString.Keys[k];
                        string queryValue=request.QueryString[getsqlkey].ToLower();
                        string getip = Find(request, keyword, getsqlkey, queryValue, (int)CheckItem.query, param.SQLInjectionLevel, param.SQLInjectionType, file);
                    }
                }
                // -----------------------防 Cookies 注入-----------------------
                if (request.Cookies != null)
                {
                    for (int k = 0; k < request.Cookies.Count; k++)
                    {
                        string getsqlkey = request.Cookies.Keys[k];
                        string cookieValue=request.Cookies[getsqlkey].Value.ToLower();
                        string getip = Find(request, keyword, getsqlkey, cookieValue, (int)CheckItem.cookie, param.SQLInjectionLevel, param.SQLInjectionType, file);
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

        private static string Find(HttpRequest request, string keyword, string key, string value, int type, int level, int SQLInjectionType,string fileName)
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
            string requestvalues = Regex.Replace(value.Trim(), "\\s+", " ");
            string[] values = requestvalues.Split(' ');
            for (int i = 0; i < values.Length; i++)
            {                
                //level=0 匹配delete后面有空格的
                //level=1 完全匹配
                  
                if ((level == 0 && values[i] == keyword && values.Length > 1) || (level == 1 && values[i] == keyword))
                { 
                    if (request.ServerVariables["HTTP_X_FORWARDED_FOR"] != null)
                    {
                        getip = request.ServerVariables["HTTP_X_FORWARDED_FOR"];
                    }
                    else
                    {
                        getip = request.ServerVariables["REMOTE_ADDR"];
                    }
                     
                    #region 记录到日志
                    if (SQLInjectionType % 2 == 1) //记录到日志
                    {
                        try
                        { 
                            using (FileStream fs = new FileStream(fileName, FileMode.Append))
                            {
                                using (StreamWriter sw = new StreamWriter(fs, Encoding.Default))
                                {
                                    StringBuilder sb = new StringBuilder();
                                    sb.Append("操作IP：" + getip + ";");
                                    sb.Append("操作时间：" + DateTime.Now.ToString() + ";");
                                    sb.Append("操作页面：" + request.ServerVariables["URL"] + ";");
                                    sb.Append("提交方式：" + optionType + ";");
                                    sb.Append("提交参数：" + key + ";");
                                    sb.Append("提交数据：" + value + ";");

                                    sw.WriteLine(sb.ToString());
                                }

                            }
                        }
                        catch (Exception ex)
                        {

                        }
                    }
                    #endregion

                    #region 记录到数据库(未实现)
                    if (SQLInjectionType ==2||SQLInjectionType==3||SQLInjectionType==6) //记录到数据库
                    {
                         //string sql = @" insert into Table values() ";
                    }
                    #endregion 

                    #region 页面输出
                    HttpContext.Current.Response.Write("<script Language=JavaScript>alert('防注入程序提示您，请勿提交非法字符！');</" + "script>");
                    HttpContext.Current.Response.Write("非法操作！您存在非法的sql注入" + "<br>");
                    
                    HttpContext.Current.Response.Write("操 作 I P ：" + getip + "<br>");
                    HttpContext.Current.Response.Write("操 作 时 间：" + DateTime.Now.ToString() + "<br>");
                    HttpContext.Current.Response.Write("操 作 页 面：" + request.ServerVariables["URL"] + "<br>");
                    HttpContext.Current.Response.Write("提 交 方 式：" + optionType + "<br>");
                    HttpContext.Current.Response.Write("提 交 参 数：" + key + "<br>");
                    HttpContext.Current.Response.Write("提 交 数 据：" + value + "<br>");
                    HttpContext.Current.Response.End();
                    #endregion  
              }
            }
           
            return getip;
        }
         

        private enum CheckItem : int
        { 
            form=1,
            query,
            cookie            
        }

    }
}
