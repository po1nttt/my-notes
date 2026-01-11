# 什么是valve？
在了解Valve之前，我们先来简单了解一下Tomcat中的`管道机制`。

我们知道，当Tomcat接收到客户端请求时，首先会使用`Connector`进行解析，然后发送到`Container`进行处理。那么我们的消息又是怎么在四类子容器中层层传递，最终送到Servlet进行处理的呢？这里涉及到的机制就是Tomcat管道机制。

管道机制主要涉及到两个名词，Pipeline（管道）和Valve（阀门）其实在最开始debug的时候，我们也可以看到这两个名词。如果我们把请求比作管道（Pipeline）中流动的水，那么阀门（Valve）就可以用来在管道中实现各种功能，如控制流速等。因此通过管道机制，我们能按照需求，给在不同子容器中流通的请求添加各种不同的业务逻辑，并提前在不同子容器中完成相应的逻辑操作。这里的调用流程可以类比为Filter中的责任链机制
![](picture/Pasted%20image%2020260111224736.png)
在Tomcat中，四大组件Engine、Host、Context以及Wrapper都有其对应的Valve类，StandardEngineValve、StandardHostValve、StandardContextValve以及StandardWrapperValve，他们同时维护一个StandardPipeline实例。
`pipeline`接口如下，继承了 `Contained`接口
```java
public interface Pipeline extends Contained {
 
    public Valve getBasic();
 
    public void setBasic(Valve valve);
 
    public void addValve(Valve valve);
 
    public Valve[] getValves();
 
    public void removeValve(Valve valve);
 
    public void findNonAsyncValves(Set<String> result);
}
```
Pipeline接口提供了各种对Valve的操作方法，如我们可以通过`addValve()`方法来添加一个Valve。下面我们再来看看Valve接口
```java
public interface Valve {
 
    public Valve getNext();
 
    public void setNext(Valve valve);
 
    public void backgroundProcess();
 
    public void invoke(Request request, Response response)
        throws IOException, ServletException;
 
    public boolean isAsyncSupported();
}
```

其中getNext()方法可以用来获取下一个Valve，Valve的调用过程可以理解成类似Filter中的责任链模式，按顺序调用。
![](picture/Pasted%20image%2020260111225004.png)
同时Valve可以通过重写`invoke()`方法来实现具体的业务逻辑
```java
class Shell_Valve extends ValveBase {
 
        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            ...
            }
        }
    }
```
下面我们通过源码看一看，消息在容器之间是如何传递的。首先消息传递到Connector被解析后，在`org.apache.catalina.connector.CoyoteAdapter#service`方法中
```java
public void service(org.apache.coyote.Request req, org.apache.coyote.Response res) throws Exception {
    Request request = (Request) req.getNote(ADAPTER_NOTES);
        Response response = (Response) res.getNote(ADAPTER_NOTES);
 
        if (request == null) {
            // Create objects
            request = connector.createRequest();
            request.setCoyoteRequest(req);
            response = connector.createResponse();
            response.setCoyoteResponse(res);
 
            // Link objects
            request.setResponse(response);
            response.setRequest(request);
 
            // Set as notes
            req.setNote(ADAPTER_NOTES, request);
            res.setNote(ADAPTER_NOTES, response);
 
            // Set query string encoding
            req.getParameters().setQueryStringCharset(connector.getURICharset());
        }
...
 
    try {
            ...
            connector.getService().getContainer().getPipeline().getFirst().invoke(   request, response);
            }
...
}
```
前面是对Request和Respone对象进行一些判断及创建操作，我们重点来看一下`connector.getService().getContainer().getPipeline().getFirst().invoke(request, response)`

首先通过`connector.getService()`来获取一个StandardService对象

接着通过`StandardService`.`getContainer().getPipeline()`获取`StandardPipeline`对象。

再通过`StandardPipeline.getFirst()`获取第一个Valve
```java
@Override
    public Valve getFirst() {
        if (first != null) {
            return first;
        }
 
        return basic;
    }
```
最后通过调用`StandardEngineValve.invoke()`来实现Valve的各种业务逻辑
```java
public final void invoke(Request request, Response response)
        throws IOException, ServletException {
 
        // Select the Host to be used for this Request
        Host host = request.getHost();
        if (host == null) {
            // HTTP 0.9 or HTTP 1.0 request without a host when no default host
            // is defined.
            // Don't overwrite an existing error
            if (!response.isError()) {
                response.sendError(404);
            }
            return;
        }
        if (request.isAsyncSupported()) {
            request.setAsyncSupported(host.getPipeline().isAsyncSupported());
        }
 
        // Ask this Host to process this request
        host.getPipeline().getFirst().invoke(request, response);
    }
```
















