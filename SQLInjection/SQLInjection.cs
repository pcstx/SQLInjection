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

            string keywords = "";
            bool enable =true;
            try
            {
                if (ConfigurationManager.AppSettings.Count > 0)
                {
                    string enableStr = ConfigurationManager.AppSettings["SQLInjectionEnable"]; //是否启用
                    if (enableStr!= null)
                    {
                        if (enableStr.ToLower() == "false" || enableStr.ToLower() == "0")
                        {
                            enable = false;
                        }
                    }

                    keywords = ConfigurationManager.AppSettings["SQLInjection"]; //追加的过滤关键词
                }

                if (enable)
                {
                    CheckSQL.Check(application, keywords);
                }
            }
            catch
            { 
            
            } 
        }

        public void Dispose()
        { 
            
        }


    }
}
