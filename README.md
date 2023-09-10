# AutoRepeater
* Burp插件，自动化挖掘SSRF，Redirect，Sqli漏洞，自定义匹配参数。
* (如果感觉对您有帮助，感觉不错的话，请您给个大大的 ⭐️❗️)
* 捡到洞欢迎分享喜悦❗️
* 有更好的判断规则，可以提交issue。
* 其他SRC常用漏洞思路，也可提交，扩展进去。
* 打包了jdk1.8和jdk18版本。

**V1.1**
* 添加了请求包相应包匹配选项（基于原请求响应，只有文本正则匹配，不占资源）
  ![iShot_2023-09-10_18 34 22](https://github.com/Lotus6/AutoRepeater/assets/63742814/52373def-d4a3-4946-addf-4e7e0cbbe163)

* 内置了未授权，shiro，ak，swagger，建议开两个窗口，一个用来匹配敏感信息，一个用来检测漏洞。
* 未授权默认未勾选，用法，进入后台后，勾选上，接口点一遍，会自动删除Cookie，看下方的 Modified 有无正常响应，即可迅速找到未授权接口，页面等。
* Bug. Type.输出的为添加时的comment，方便定位什么敏感信息。
  ![iShot_2023-09-10_18 35 44](https://github.com/Lotus6/AutoRepeater/assets/63742814/2a634410-beff-49d5-bf09-a4f749aca19d)


**V1.0**

1. 效果图
* 低版本burp
![iShot_2023-09-02_17 03 04](https://github.com/Lotus6/AutoRepeater/assets/63742814/6a806fe8-2c8f-4233-a60e-9d9909e66425)
* 高版本burp
<img width="1318" alt="image" src="https://github.com/Lotus6/AutoRepeater/assets/63742814/76a22d76-a06b-403c-802c-c3125691d164">


2. Config配置

* 开启插件的同时，选择开启SSRF，Redirect，Sqli模块的按钮，dnslog token等

![iShot_2023-09-02_17 16 55](https://github.com/Lotus6/AutoRepeater/assets/63742814/e17785e0-6d40-4bac-a62c-f1d70d1a5e50)


* 在Replacements中，可自定义选择匹配的参数，也就是这个漏洞常见的参数点，我也内置了些，自己选择添加删除
![iShot_2023-09-02_17 21 51](https://github.com/Lotus6/AutoRepeater/assets/63742814/af092b05-bfc8-4389-9e3e-a57c850acab4)




##

**原工具地址**

https://github.com/nccgroup/AutoRepeater

* 修复了，原工具issue中，一直在问的json匹配不到问题



##

**免责声明**



本工具仅能在取得足够合法授权的企业安全建设中使用，在使用本工具过程中，您应确保自己所有行为符合当地的法律法规。


如您在使用本工具的过程中存在任何非法行为，您将自行承担所有后果，本工具所有开发者和所有贡献者不承担任何法律及连带责任。


除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。


您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
