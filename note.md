##### 1. 中间件

```python
def simple_middleware(get_response):
    # 此处编写的代码仅在Django第一次配置和初始化的时候执行一次。

    def middleware(request):
        # 此处编写的代码会在每个请求处理视图前被调用。
        # CSRF框架请求伪造
        # 设置ip黑名单

        response = get_response(request)

        # 此处编写的代码会在每个请求处理视图之后被调用。

        return response

    return middleware
```

CSRF_Protect

@before_request

QueryDict



##### 2. 子类视图使用

```python
# 定义类视图，实现以下接口:
# 需求1：写一个视图，只提供一个接口
	1. 获取一组图书数据 GET /books/
    class BookListView(ListModelMixin, GenericAPIView):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer
        
        def get(self, request)
			return self.list(request)
        
    class BookListView(ListAPIView):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer
   
# 需求2：写一个视图，只提供一个接口
	1. 获取指定的图书数据 GET /books/(?P<pk>\d+)/
    class BookDetailView(GenericAPIVew):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer
        
        def get(self, request, pk)
        	obj = self.get_object()
            serializer = self.get_serializer(obj)
            return Response(serializer.data)
        
    class BookDetailView(RetrieveModelMixin, GenericAPIVew):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer
        
        def get(self, request, pk)
        	return self.retreive(request, pk)
            
   class BookDetailView(RetrieveAPIVew):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer


# 需求3：写一个视图，只提供两个接口
	1. 获取指定的图书数据 GET /books/(?P<pk>\d+)/
    2. 更新指定的图书数据 PUT /books/(?P<pk>\d+)/
    
    class BookDetailView(RetrieveUpdateAPIView):
        queryset = BookInfo.objects.all()
        serializer_class = BookInfoSerializer
```



##### 3. 搜索包目录

搜索包的目录列表：

import sys

sys.path: list列表，包含搜索的目录

[`目录1`, `目录2`, `目录3`, ...]

from ... import ...



##### 4. 注册用户信息的存储

用户表

```
ID
用户名
密码
手机号
邮箱
是否管理员
是否注销
```

定义模型类，进行迁移生成表。



##### 5. 业务功能实现思路

用户注册-子业务：

1）获取短信验证码

2）保存注册用户的信息

3）用户名是否存在

4）手机号是否存在

每个API接口设计:

```
1. 确定url地址和请求方式
2. 确定接口所需的参数以及传递参数格式
3. 确定响应数据和格式
```

##### 附录

码云项目地址：`https://gitee.com/smartliit/meiduo_sh21.git`



##### Day02

##### 1. 短信验证码获取

```http
API: GET /sms_codes/(?P<mobile>1[3-9]\d{9})/
参数:
	通过url地址传递`mobile`参数
响应:
	{
        "message": "OK"
	}
```

基本业务：

1）随机生成6位数字作为短信验证码内容

2）在redis中保存短信验证码内容，以`mobile`为key，以`验证码内容`为value

3）使用云通讯发送短信

4）返回应答，发送成功

客户端向服务器传递参数途径:

1）url传递

2）查询字符串

3）通过请求体传递（表单，json）

4）通过请求头传递参数

```
$.ajax({
    'headers': {
        'X-CSRFToken': '',
    }
})
```



短信发送逻辑补充：

1）短信发送60s时间间隔的限制

2）redis管道使用

​	可以向redis管道中添加多个命令，然后一次性执行。



##### 2. 跨域请求

同源策略：对于两个url地址，如果它们的协议，ip和端口完全一致，那么这两个地址就是同源的，否则非同源的。



当浏览器发起请求时，如果来源页面的地址和被请求的地址不是同源，那么这个请求就是跨域请求。

源地址：`http://127.0.0.1:8080`

被请求地址：`http://127.0.0.1:8000`



CORS跨域请求限制：

浏览器在发起ajax异步跨域请求时，浏览器会进行CORS跨域请求限制。

浏览器发起请求时，会在请求中携带请求头：

> Origin: 源请求地址

当被请求的服务器收到请求之后，如果允许源地址进行跨域请求，需要在响应中携带响应头：

> Access-Control-Allow-Origin: 源请求地址

浏览器在收到响应之后，如果发现响应头中没有`Access-Control-Allow-Origin: 源请求地址`，浏览器会直接将请求驳回，报错。



<img src=''>

<form action=''>

​	...

</form>



`扩展内容:`

跨站请求属不属于跨域请求？

答：跨站请求属于跨域请求。

##### 3. 本地域名设置

live-server: 127.0.0.1:8080 -> `www.meiduo.site`

后端API服务器: 127.0.0.1:8000 -> `api.meiduo.site`



通过域名访问网站时，进行DNS解析之前，会先到本地的`/etc/hosts`文件中查询ip和域名的对应关系，如果找到则直接访问对应的ip，否则再进行DNS解析(`根据域名获取对应的ip`)，然后访问ip所对应的服务器。

> 注：想要通过域名访问Django服务器时，需要将该域名添加到配置文件的ALLOWED_HOSTS配置项中。



`扩展内容`：

1）从输入URL到浏览器显示页面发生了什么？

答：`https://www.cnblogs.com/kongxy/p/4615226.html`。



##### 4. Celery异步任务队列

本质：通过创建进程调用函数来实现任务的异步执行。

概念：

​	  任务发出者：发出任务(`要执行函数`)消息

​	任务执行者：提前创建的进程

​	中间人(任务队列)：存放发出任务消息

使用：

1）安装：pip install celery

2）创建一个Celery类的实例对象并进行相应设置

```python
# main.py
from celery import Celery

# 创建Celery类对象
celery_app = Celery('demo')

# 加载配置信息
celery_app.config_from_object('配置文件包路径')

# celery worker启动时自动发现任务函数
celery_app.auto_discover_tasks([...])
```

```python
# config.py
# 设置中间人地址
# broker_url = 'redis://<ip>:<port>/<db>'
broker_url = 'redis://172.16.179.139:6379/3'
```

3）封装任务函数

```python
@celery_app.task(name='send_sms_code')
def send_sms_code(a, b):
	# 任务函数的代码...
```

4）启动worker(创建工作进程)

```bash
celery -A 'celery_app对象所在文件包路径' worker -l info
```

5）发出任务消息

```python
send_sms_code.delay(1, 3)
```



##### 5. 用户名是否存在(获取用户名的数量)

```http
API: GET /usernames/(?P<username>\w{5,20})/count/
参数:
	传递用户名`username`
响应:
	{
        "username": "用户名",
        "count": "数量"
	}
```

##### 6. 手机号是否存在(获取手机号的数量)

```http
API: GET /mobiles/(?P<mobile>1[3-9]\d{9})/count/
参数:
	传递手机号`mobile`
响应:
	{
        "mobile": "手机号",
        "count": "数量"
	}
```

##### 7. 今日内容小结 

1. 短信验证码发送-基本业务逻辑

2. 短信发送60s间隔限制

3. redis管道的使用

4. CORS跨域请求限制

   > Origin: 源地址

   > Access-Control-Allow-Origin: 源地址

5. 本地域名的设置

6. celery异步任务队列使用

7. 用户名和手机号是否存在



### Day03

##### 1. 注册用户信息的保存

创建新用户。

```http
API: POST /users/
参数:
	{
        "username": "用户名",
        "password": "密码",
        "password2": "重复密码",
        "mobile": "手机号",
        "sms_code": "短信验证码",
        "allow": "是否同意", # "true": 同意
	}
响应:
	{
        "id": "用户id",
        "username": "用户名",
        "mobile": "手机号",
        "token": "jwt token"
	}
```

##### 2. JWT认证

`session认证机制`:

```http
1. 获取账户和密码
2. 对账户和密码进行校验
3. 在session中保存用户的登录状态
	session['user_id'] = 2
	session['username'] = 'smart'
4. 返回应答
```

在返回应答时，会让客户端保存cookie(`session标识`)，之后客户端再访问服务器时，会把`session标识`传递给服务器，服务器就可以根据`session标识`取出对应的session的数据，对用户的身份进行检验。

缺点：

1）session数据存储在服务器端，如果登录用户过多，会过多占用服务器存储空间。

2）session依赖于cookie，如果cookie被利用，可能会产生CSRF伪造(`跨站请求的伪造`)。

3）在分布式的网站应用中，如果session存储在服务器内存，session共享会产生问题，不利于网站扩展。

优点：

1）可以保存敏感的数据。

`jwt认证机制`:

```http
1. 获取账户和密码
2. 对账户和密码进行校验
3. 由服务器生成一个字符串(jwt token)，保存着用户的身份信息
	公安局->身份证(jwt token)
4. 返回应答，将jwt token返回给客户端
```

客户端需要将jwt token进行保存，在之后请求服务器时，如果需要进行身份验证，就需要将jwt token传递给服务器，由服务器校验jwt token有效性。

优点：

1）jwt token由客户端进行存储，不会占用服务器的存储空间。

缺点：

2）不适合存储敏感的数据。

`jwt token的组成`:

​	一个字符串，由3部分组成，用`.`隔开。

头部(header):

```python
{
    "token类型", # "jwt",
    "签名加密算法",
}
```

使用base64进行编码加密，产生的字符串就是`header`。

载荷(`payload`)：保存有效数据。

```python
{
    "user_id": 2,
    "username": "smart",
    "mobile": "13155667788",
    "email": "",
    "exp": "token过期时间"
}
```

使用base64进行编码加密，产生的字符串就是`payload`，base64编码加密很容易被解密。

签名(`signature`)：防止jwt token被伪造。

```html
签名的生成？
答：服务器将header和payload字符串进行拼接，用.隔开，然后使用一个只有服务器知道的密钥(secret_key)对生成的字符串进行加密，加密之后的字符串就是签名。


签名的校验？
答：服务器将客户端发送的jwt token中将header和payload字符串进行拼接，用.隔开，然后使用服务器自己的密钥进行加密，然后将加密之后的内容和客户端传递的jwt token中的signature进行对比，如果一致，验证通过，否则jwt token就是伪造。
```

`jwt token使用注意点`:

1）payload中不要存放过于敏感的数据。

2）如果可以，请使用https协议。

3）服务器的密钥需要保存好。



##### 3. DRF JWT 扩展

功能: 可以生成jwt token，也可以对jwt token进行校验。

使用:

​	pip install djangorestframework-jwt

配置:

```python
REST_FRAMEWORK = {
   	...
    # 认证设置
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # 引入jwt的认证机制，客户端给服务器传递jwt token之后，此认证机制就会去检验jwt token
        # 数据的有效性，如果无效，会直接返回401(未认证)
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
}

# JWT 扩展的配置
JWT_AUTH = {
    # 设置生成jwt token数据的有效时间
    'JWT_EXPIRATION_DELTA': datetime.timedelta(days=1),
}
```

手动生成jwt token:

```python
from rest_framework_jwt.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

payload = jwt_payload_handler(user)
token = jwt_encode_handler(payload)
```

浏览器本地保存:

```python
1. sessionStorage 浏览器关闭即失效
2. localStorage 长期有效
```

##### 

##### 4. 用户登录

创建一个jwt token。

```http
API: POST /authorizations/
参数:
	{
        "username": "用户名",
        "password": "密码"
	}
响应:
	{
		"user_id": "用户id",
        "username": "用户名",
        "token": "jwt token"
	}
```



```python
class UserAuthorizeView(APIView):
    def post(self, request):
        """
        用户登录:
        1. 获取参数并进行校验(参数完整性)
        2. 对用户名和密码进行验证
        3. 生成一个jwt token
        4. 返回应答，登录成功
        """
        pass
```



jwt 扩展中提供了一个登录视图`obtain_jwt_token`，这个视图就是接受`username`和`password`，然后进行校验，并且在校验通过之后会生成一个`jwt token`并返回，但是响应数据中只有jwt token。



##### 5. 自定义jwt扩展登录视图响应数据的函数

1）自定义响应数据的函数

```python
def jwt_response_payload_handler(token, user=None, request=None):
    """
    自定义jwt扩展登录视图的响应数据函数
    """
    return {
        'user_id': user.id,
        'username': user.username,
        'token': token
    }
```

2) 设置jwt扩展的配置项

```python
# JWT扩展配置
JWT_AUTH = {
    ...
    # 指定jwt 扩展登录视图响应数据函数
    'JWT_RESPONSE_PAYLOAD_HANDLER':
    'users.utils.jwt_response_payload_handler',
}
```



##### 6. 登录账户既支持用户名也支持手机号

```python
obtain_jwt_token(此登录视图中并没有自己实现账户和密码校验的代码，而是调用Django认证系统中的函数)
-> from django.contrib.auth import authenticate(此方法中也没有实现账户和密码校验的代码，而是调用Django认证后端类中的authenticate函数进行校验)
-> from django.contrib.auth.backends import ModelBackend(这个类是Django的默认认证后端类)

class ModelBackend(object):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        """此方法最终实现了账户和密码校验的代码，但是账户仅支持用户名"""
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
```



##### 7. QQ登录效果

当用户使用QQ登录时，需要判断QQ用户和网站的用户是否已经绑定过，如果绑定过直接让对应的用户登录成功，如果没有绑定过需要先让用户进行绑定操作，绑定之后才能登录成功。



##### 8. 今日内容小结

1）注册用户信息的保存API

2）jwt 认证机制

3）jwt扩展

作用: 生成(签发)jwt token 和 校验jwt token

4）sessionStorage和localStorage

在浏览器本地存储数据。

5）用户登录-jwt扩展登录视图`obtain_jwt_token`

```
url(r'^authorizations/$', obtain_jwt_token), # 登录视图配置
```

6）用户登录-自定义jwt 扩展登录视图响应数据函数

7）用户登录-登录账户支持用户名和手机号

​	自定Django认证系统后端类

​	   修改`AUTHENTICATION_BACKENDS`配置项。

8）QQ登录效果演示。









































