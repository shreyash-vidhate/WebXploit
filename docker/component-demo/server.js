const http=require("http");
const inventory={component:"demo-parser",version:"1.0.0",status:"outdated",advisory:"WEBXPLOIT-A06-DEMO",note:"Intentional local-lab component inventory for dependency-risk validation."};
http.createServer((req,res)=>{if(req.url!=="/component-report"){res.writeHead(404,{"Content-Type":"application/json"});return res.end(JSON.stringify({error:"Not found"}));}res.writeHead(200,{"Content-Type":"application/json","X-WebXploit-Lab":"A06"});res.end(JSON.stringify(inventory));}).listen(3007,"0.0.0.0");
