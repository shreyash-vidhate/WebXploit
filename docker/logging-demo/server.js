const http=require("http"),fs=require("fs");
const LOG="/telemetry/a09-app.log";
http.createServer((req,res)=>{
 const u=new URL(req.url,"http://localhost");
 if(u.pathname!=="/search"){res.writeHead(404,{"Content-Type":"application/json"});return res.end(JSON.stringify({error:"Not found"}));}
 const q=u.searchParams.get("q")||"";fs.appendFileSync(LOG,`${new Date().toISOString()} query=${q}\n`);
 res.writeHead(200,{"Content-Type":"application/json","X-WebXploit-Lab":"A09"});res.end(JSON.stringify({status:"logged",query:q}));
}).listen(3005,"0.0.0.0");
