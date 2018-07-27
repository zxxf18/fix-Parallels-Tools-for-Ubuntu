# Parallels 13.3.1以下Ubuntu安装Tools error处理
在mac上，用paralles虚拟机安装完ubuntu时，在Parallels 版本小于13.3.1且ubuntu版本大于14.4.4时会出现paralles tools安装失败的现象，具体如下图

![图片描述][1]

![图片描述][2]

## 情况一：Parallels 版本小于12，且Ubuntu版本小于16时
可以通过如下步骤修复：

1. 挂载 Parallels Tools镜像
2. 打开一个terminal，执行如下命令（或者手动复制后添加相应权限）  

    cd /media/<username>/Parallels\ Tools/
    mkdir ~/Desktop/tools
    cp -pr * ~/Desktop/tools
    cd ~/Desktop/tools
    chmod -R 777 kmods

3. 用解压缩工具打开~/Desktop/tools/kmods目录下的prl_mod.tar.gz
4. 在压缩工具里用gedit打开./prl_tg/Toolgate/Guest/Linux/prl_tg/prltg.c，在其他include的代码后面添加如下代码  

        #include <linux/vmalloc.h>

5. 在压缩工具里用gedit打开./prl_fs/SharedFolders/Guest/Linux/prl_fs/inode.c，找到prlfs_follow_link (大约在650行)并修改为如下代码(包括 compat_follow_link_t)

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
        #define compat_follow_link_t const char*
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
        #define compat_follow_link_t void*
        #else
        #define compat_follow_link_t int
        #endif
        
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
        static compat_follow_link_t prlfs_follow_link(struct dentry *dentry, void  **cookie)
        #else
        static compat_follow_link_t prlfs_follow_link(struct dentry *dentry, struct nameidata *nd)
        #endif
        {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
            return do_read_symlink(dentry);
        #else
        
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
                nd_set_link(nd, do_read_symlink(dentry));
            #endif
        
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
                return NULL;
            #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
                return 0;
            #else
                return vfs_follow_link(nd, do_read_symlink(dentry));
            #endif
        #endif
        }

6. 在~/Desktop/tools目录执行如下命令:  
		sudo ./install

## 情况二：不符合以上情况或上面没解决时尝试

1. 挂载 Parallels Tools镜像
2. 打开一个terminal，执行如下命令（或者手动复制后添加相应权限）  
        cd /media/<username>/Parallels\ Tools/
    	mkdir ~/Desktop/parallels_fixed
    	cp -pr * ~/Desktop/parallels_fixed
    	cd ~/Desktop/parallels_fixed
    	chmod -R 777 kmods
3. 用解压缩工具打开~/Desktop/tools/kmods目录下的prl_mod.tar.gz
4. 修改3个文件

* 进入"prl_eth/pvmnet/" (cd ~/Desktop/parallels_fixed/kmods/prl_eth/pvmnet) 目录，修改pvmnet.c文件，在438行，修改   


    MODULE_LICENSE("Parallels");
    为
    MODULE_LICENSE("GPL");
然后保存并更新压缩包  

* 进入"prl_tg/Toolgate/Guest/Linux/prl_tg/" (cd ~/Desktop/parallels_fixed/kmods/prl_tg/Toolgate/Guest/Linux/prl_tg) 目录，修改prltg.c文件，在1535行，修改   

	
			MODULE_LICENSE("Parallels");
			为
			MODULE_LICENSE("GPL");
然后保存并更新压缩包

* 进入"prl_fs_freeze/Snapshot/Guest/Linux/prl_freeze/" (cd ~/Desktop/parallels_fixed/kmods/prl_fs_freeze/Snapshot/Guest/Linux/prl_freeze)目录，修改prl_fs_freeze.c文件，在212行，修改   
		
	
			void thaw_timer_fn(unsigned long data)
			{
			   struct work_struct *work = (struct work_struct *)data;
			   
			   schedule_work(work);
			}
			为
			void thaw_timer_fn(unsigned long data)
			{
			   struct work_struct *work = (struct work_struct *)data;
			   
			   schedule_work(work);
			}
			
			void thaw_timer_fn_new_kernel(struct timer_list *data)
			{
			   struct work_struct *work = data->expires;
			   
			   schedule_work(work);
			}
			
修改原220行
			DEFINE_TIMER(thaw_timer, thaw_timer_fn, 0, (unsigned long)&(thaw_work));
			为
			
			#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
			DEFINE_TIMER(thaw_timer, thaw_timer_fn_new_kernel);
			#else
			DEFINE_TIMER(thaw_timer, thaw_timer_fn, 0, (unsigned long)&(thaw_work));
			#endif
	

然后保存并更新压缩包
		
最后在~/Desktop/parallels_fixed目录执行如下命令:  
			sudo ./install
	
## 其他
* 在parallels 13.3.1版本中已经对tools在ubuntu目前的最新版18.04提供了支持，升级parallels是最简单的解决方案
* 前文的两种方法是在网上到处搜索实践比较得出的有效的方法，这里感谢上面两个方法的提供者
* 如果你不想升级parallels，也觉得按上面说的改文件太麻烦，这里提供一份我修改好的供大家使用，下载然后给权限，执行sudo ./install即可 ([fix-Parallels-Tools-for-Ubuntu][3])

ref:
>>[参考1][4]
>>[参考2][5]


  [1]: https://segmentfault.com/img/bVberh8?w=580&h=469
  [2]: https://segmentfault.com/img/bVberib?w=580&h=469
  [3]: https://github.com/zxxf18/fix-Parallels-Tools-for-Ubuntu
  [4]: https://blog.csdn.net/wangjian5748/article/details/51852698/
  [5]: https://gist.github.com/rudolfratusinski/a4d9e3caff11a4d9d81d2e84abc9afbf
