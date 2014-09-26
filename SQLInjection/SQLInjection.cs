using System;
using System.Collections.Generic; 
using System.Text;
using System.Web;
using System.Configuration; 

namespace SQLInjection
{
    public class SQLInjection : IHttpModule
    {
        public void Init(HttpApplication application)
        {
            application.BeginRequest += new EventHandler(application_BeginRequest);
        }

        void application_BeginRequest(object sender, EventArgs e)
        {
            HttpApplication application = (HttpApplication)sender;
             
            try
            {
                SQLInjectionParam param = new SQLInjectionParam();
                if (ConfigurationManager.AppSettings.Count > 0)
                { 
                    string enableStr = ConfigurationManager.AppSettings["SQLInjectionEnable"]; //是否启用
                    if (enableStr!= null)
                    {
                        if (enableStr.ToLower() == "false" || enableStr.ToLower() == "0")
                        {
                            param.SQLInjectionEnable = false;
                        }
                    }

                    param.SQLInjectionLevel = ConvertToInt(ConfigurationManager.AppSettings["SQLInjectionLevel"]); //过滤等级
                    param.SQLInjection = ConfigurationManager.AppSettings["SQLInjection"]; //追加的过滤关键词
                    param.SQLInjectionType = ConvertToInt(ConfigurationManager.AppSettings["SQLInjectionType"]); //过滤方法
                    string logFileName = ConfigurationManager.AppSettings["SQLInjectionLogFile"]; //日志记录文件
                    if (!string.IsNullOrEmpty(logFileName))
                    {
                        param.SQLInjectionLogFile = logFileName;
                    }
                }

                if (param.SQLInjectionEnable)
                { 
                    CheckSQLReg.Check(application, param);
                    CheckSQL.Check(application,param);
                }
            }
            catch(Exception ex)
            { 
            
            } 
        }

        private static int ConvertToInt(string obj)
        {
            int result = 0;
            int.TryParse(obj, out result);
            return result;
        }

        public void Dispose()
        { 
            
        }
         


    } 
}
