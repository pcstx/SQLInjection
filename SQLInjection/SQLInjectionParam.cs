using System;
using System.Collections.Generic;
using System.Text;

namespace SQLInjection
{
    public class SQLInjectionParam
    {
        private bool _enable = true;
        /// <summary>
        /// 是否启用注入检验
        /// </summary>
        public bool SQLInjectionEnable
        {
            get { return _enable; }
            set { _enable = value; }
        }

        private string _keywords = "";
        /// <summary>
        /// 追加关键词
        /// </summary>
        public string SQLInjection
        {
            get { return _keywords; }
            set { _keywords = value; }
        }

        private int _level = 0;
        /// <summary>
        /// 过滤等级
        /// </summary>
        public int SQLInjectionLevel
        {
            get { return _level; }
            set { _level = value; }
        }

        private int _type = 0;
        /// <summary>
        /// 过滤类型
        /// </summary>
        public int SQLInjectionType
        {
            get { return _type; }
            set { _type = value; }
        }

        private string _logFile = @"Log/log" + DateTime.Today.ToShortDateString() + @".txt";
        /// <summary>
        /// 日志记录文件
        /// </summary>
        public string SQLInjectionLogFile
        {
            get { return _logFile; }
            set { _logFile = value; }
        }
    }
}
