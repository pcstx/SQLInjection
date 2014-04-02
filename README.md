SQLInjection
============

SQL提交防注入


--- 使用方法  -------------------------------------
在要用的项目webconfig文件中增加相应配置

<configuration> 
  <system.web> 
    <httpModules>
       <add name="SQLInjection" type="SQLInjection.SQLInjection"/> 
   </httpModules> 
  </system.web>
  
    <appSettings>
        <add key="SQLInjectionEnable" value="1"/> <!-- 是否启用;默认启用 -->
        <add key="SQLInjection" value="pcstx"/>  <!-- 追加过滤关键词;常用的已内置 -->
    </appSettings>
</configuration>
