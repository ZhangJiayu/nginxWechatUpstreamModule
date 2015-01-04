nginxWechatUpstreamModule
=========================

Nginx upstream module based on post content. Designed for wechat.  

This module is open sourced under the same license as Nginx.  

You could read doc/doc.txt and following installation guide.

You should also be familiar with wechat development. If not, you could learn it at mp.weixin.qq.com

Installation
---------------------------
Installation Instruction:  
Tested in ubuntu 14.04  
First, you must have libxml installed. If not, you need:  
sudo apt-get install libxml2-dev  
Then copy the libxml folder in usr/include/libxml2 to usr/include so that my module could include it.  

And you need to use our nginx with the module. Other nginx may not work.  

Then you could configure nginx:  
First go to nginx-1.6.0 folder. Execute ./configure --add-module=../module  
The go to objs/makefile, delete -Werror in line 2.  
Then return to nginx-1.6.0 folder, make, sudo make install.  
Then you could find nginx in /usr/local/nginx  
We give an conf file for example. The testups in upstream block is what you need to write.  
You could use regular expression in xml body to match each server. You could use re in Content, MsgType, CreateTime, FromUserName and so on. If the message couldn't be matched by any server, it's sent to the last server.  


Thanks
-----------------------------------------------
Thanks for Evan Miller's tutorial and upstream hash module. Many of my source code comes from that module.


Thanks for developer of libxml and pcre.  

Thanks for Liuqiang teacher, Chen Huarong, Jiang Linnan, Gong Dahan, Yu Zeming and all of my classmates.

Thanks for open source!