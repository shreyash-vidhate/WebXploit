const http=require("http");
let attempts=0;
http.createServer((req,res)=>{
 if(req.method!=="POST"||req.url!=="/login"){res.writeHead(404,{"Content-Type":"application/json"});return res.end(JSON.stringify({error:"Not found"}));}
 let b="";req.on("data",c=>b+=c);req.on("end",()=>{attempts++;res.writeHead(401,{"Content-Type":"application/json","X-WebXploit-Lab":"A07"});res.end(JSON.stringify({error:"Invalid credentials",attempt:attempts}));});
}).listen(3006,"0.0.0.0");
