require('dotenv').config();
var express=require('express');
var cors=require('cors');
var jwt=require('jsonwebtoken');
var bcrypt=require('bcryptjs');
var Anthropic=require('@anthropic-ai/sdk');
var app=express();
var PORT=process.env.PORT;
var SECRET='IronAI2026';
var FREE=10;
var DB={};
app.use(cors({origin:'*',methods:['GET','POST','OPTIONS'],allowedHeaders:['Content-Type','Authorization']}));
app.use(express.json());
app.use(express.static('public'));
function mk(){var d=new Date();return d.getFullYear()+'-'+(d.getMonth()+1);}
function uid(){return Math.random().toString(36).slice(2)+Date.now().toString(36);}
function auth(req,res,next){
var h=req.headers.authorization;
if(!h||!h.startsWith('Bearer '))return res.status(401).json({error:'Non autorise'});
try{var p=jwt.verify(h.slice(7),SECRET);var u=DB[p.email];if(!u)return res.status(401).json({error:'Introuvable'});req.user=u;next();}
catch(e){return res.status(401).json({error:'Token invalide'});}
}
app.post('/auth/register',async function(req,res){
var email=req.body.email,pw=req.body.password,prenom=req.body.prenom||'';
if(!email||!pw)return res.status(400).json({error:'Email et mot de passe requis'});
if(pw.length<6)return res.status(400).json({error:'Mot de passe trop court'});
if(DB[email])return res.status(409).json({error:'Email deja utilise'});
var hash=await bcrypt.hash(pw,10);
DB[email]={id:uid(),email:email,prenom:prenom,hash:hash,plan:'free',msgs:0,mk:mk()};
var tok=jwt.sign({email:email},SECRET,{expiresIn:'30d'});
res.json({token:tok,user:{email:email,prenom:prenom,plan:'free',messagesLeft:FREE}});
});
app.post('/auth/login',async function(req,res){
var email=req.body.email,pw=req.body.password;
var u=DB[email];
if(!u)return res.status(401).json({error:'Email ou mot de passe incorrect'});
if(!await bcrypt.compare(pw,u.hash))return res.status(401).json({error:'Email ou mot de passe incorrect'});
if(u.mk!==mk()){u.msgs=0;u.mk=mk();}
var tok=jwt.sign({email:email},SECRET,{expiresIn:'30d'});
var left=u.plan==='premium'?999:Math.max(0,FREE-u.msgs);
res.json({token:tok,user:{email:u.email,prenom:u.prenom,plan:u.plan,messagesLeft:left}});
});
app.get('/auth/me',auth,function(req,res){
var u=req.user;
if(u.mk!==mk()){u.msgs=0;u.mk=mk();}
var left=u.plan==='premium'?999:Math.max(0,FREE-u.msgs);
res.json({email:u.email,prenom:u.prenom,plan:u.plan,messagesLeft:left});
});
app.post('/coach/chat',auth,async function(req,res){
var u=req.user;
if(u.mk!==mk()){u.msgs=0;u.mk=mk();}
if(u.plan==='free'&&u.msgs>=FREE)return res.status(402).json({error:'quota_exceeded',message:'Messages gratuits epuises.',messagesLeft:0});
var msgs=req.body.messages,sys=req.body.systemPrompt;
if(!msgs||!Array.isArray(msgs))return res.status(400).json({error:'Messages requis'});
var clean=msgs.slice(-10).map(function(m){return{role:m.role==='assistant'?'assistant':'user',content:String(m.content).slice(0,2000)};});
try{
var client=new Anthropic({apiKey:process.env.ANTHROPIC_API_KEY});
var r=await client.messages.create({model:'claude-opus-4-6',max_tokens:600,system:sys||'Tu es IronCoach, expert musculation. Reponds en francais.',messages:clean});
u.msgs++;
var left=u.plan==='premium'?999:Math.max(0,FREE-u.msgs);
res.json({text:r.content[0]?r.content[0].text:'',messagesLeft:left});
}catch(e){res.status(500).json({error:'Erreur serveur.'});}
});
app.get('/',function(req,res){res.json({status:'ok',app:'IronAI'});});
app.listen(PORT,function(){console.log('IronAI running on port '+PORT);});
